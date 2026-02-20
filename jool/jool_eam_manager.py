#!/usr/bin/env python3
"""
Jool SIIT/NAT64 EAM (Explicit Address Mapping) Manager

This script manages Jool SIIT and NAT64 instances and IPv4-IPv6 EAM mappings in an idempotent manner.

Features:
- Sets up kernel modules (jool, jool_siit)
- Creates Jool SIIT or NAT64 instance if not exists
- Manages EAM mappings from YAML configuration (SIIT mode only)
- Idempotent: removes mappings not in config, adds missing ones
- Supports both SIIT and NAT64 modes
- Optional pool6 for SIIT (can work with EAM only)
- Multiple IPv4 pool4 addresses for NAT64 (--pool4 repeated on CLI or comma-separated env var)
- Idempotent pool4 sync: per-protocol entries are added/removed to match desired state
- ICMP ID range support for NAT64 pool4 (via --icmp flag)
"""

import subprocess
import sys
import yaml
import logging
import os
import ipaddress
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def ipv4_to_ipv6_embedded(ipv4_addr: str, ipv6_prefix: str) -> str:
    """
    Convert an IPv4 address to an IPv6 address by embedding it in a prefix.

    This function supports several embedding methods:
    - Standard embedding: Concatenate IPv4 octets to IPv6 prefix
    - Well-known prefix: 64:ff9b::/96 + IPv4

    Args:
        ipv4_addr: IPv4 address (e.g., "192.0.2.1" or "192.0.2.1/32")
        ipv6_prefix: IPv6 prefix (e.g., "2001:db8::/96" or "64:ff9b::/96")

    Returns:
        Full IPv6 address with embedded IPv4

    Example:
        ipv4_to_ipv6_embedded("192.0.2.1", "2001:db8::/96")
        -> "2001:db8::c000:201"  (192=0xC0, 0=0x00, 2=0x02, 1=0x01)
    """
    # Parse IPv4 address (remove prefix if present)
    ipv4_str = ipv4_addr.split('/')[0]
    ipv4_obj = ipaddress.IPv4Address(ipv4_str)

    # Parse IPv6 prefix
    ipv6_net = ipaddress.IPv6Network(ipv6_prefix, strict=False)
    prefix_len = ipv6_net.prefixlen

    # Convert IPv4 to 32-bit integer
    ipv4_int = int(ipv4_obj)

    # Get the prefix as an integer
    prefix_int = int(ipv6_net.network_address)

    # Calculate how many bits we need to shift the IPv4 address
    # For /96 prefix, we shift left by 32 bits (128 - 96 - 32 = 0, so shift right by 0)
    # For /64 prefix, we shift left by 64 bits (128 - 64 - 32 = 32, so shift right by 0, left by 32)
    shift_bits = 128 - prefix_len - 32

    if shift_bits < 0:
        raise ValueError(f"IPv6 prefix /{prefix_len} is too long to embed IPv4 address")

    # Create the full IPv6 address by combining prefix and IPv4
    ipv6_int = prefix_int | (ipv4_int << shift_bits)
    ipv6_addr = ipaddress.IPv6Address(ipv6_int)

    return str(ipv6_addr)


def parse_eam_mapping(ipv4: str, ipv6: str, auto_convert: bool = False) -> Tuple[str, str]:
    """
    Parse and optionally convert EAM mapping entries.

    Args:
        ipv4: IPv4 address or prefix
        ipv6: IPv6 address/prefix or "auto" for automatic conversion
        auto_convert: Enable automatic conversion when ipv6="auto"

    Returns:
        Tuple of (ipv4_formatted, ipv6_formatted)

    Examples:
        parse_eam_mapping("192.0.2.1", "2001:db8::1")
        -> ("192.0.2.1", "2001:db8::1")

        parse_eam_mapping("192.0.2.1", "auto:2001:db8::/96", auto_convert=True)
        -> ("192.0.2.1", "2001:db8::c000:201")

        parse_eam_mapping("192.0.2.0/24", "auto:2001:db8::/96", auto_convert=True)
        -> ("192.0.2.0/24", "2001:db8::/120")
    """
    ipv4_clean = ipv4.strip()
    ipv6_clean = ipv6.strip()

    # Check if IPv6 is set to auto-convert
    if ipv6_clean.startswith("auto:") or ipv6_clean.lower() == "auto":
        if not auto_convert:
            raise ValueError(f"Auto-conversion requested for {ipv4} but auto_convert is disabled")

        # Extract prefix if provided
        if ipv6_clean.startswith("auto:"):
            prefix = ipv6_clean[5:].strip()
        else:
            # Use default well-known prefix
            prefix = "64:ff9b::/96"

        # Check if it's a network or single address
        if '/' in ipv4_clean:
            # It's a network - convert to IPv6 network
            ipv4_net = ipaddress.IPv4Network(ipv4_clean, strict=False)
            ipv6_prefix_net = ipaddress.IPv6Network(prefix, strict=False)

            # Calculate the IPv6 prefix length
            # IPv4 prefix bits + IPv6 prefix length
            ipv4_prefix_len = ipv4_net.prefixlen
            ipv6_base_prefix_len = ipv6_prefix_net.prefixlen
            ipv6_final_prefix_len = ipv6_base_prefix_len + ipv4_prefix_len

            # Get the base address by embedding the network address
            base_ipv6 = ipv4_to_ipv6_embedded(str(ipv4_net.network_address), prefix)
            ipv6_clean = f"{base_ipv6}/{ipv6_final_prefix_len}"
        else:
            # Single address
            ipv6_clean = ipv4_to_ipv6_embedded(ipv4_clean, prefix)

    return ipv4_clean, ipv6_clean


def validate_icmp_id_range(icmp_id_range: str) -> None:
    """
    Validate an ICMP ID range string.

    ICMP Identifiers are 16-bit unsigned integers (0-65535).  They serve the
    same session-tracking role for ICMP Echo that port numbers do for TCP/UDP,
    and Jool exposes them through the ``--icmp`` flag on ``pool4 add/remove``.

    Args:
        icmp_id_range: Range string such as "0-65535", "1024-2047", or a
                       single ID like "100".

    Raises:
        ValueError: if the format is invalid or values are out of [0, 65535].
    """
    parts = icmp_id_range.split('-')
    try:
        if len(parts) == 1:
            val = int(parts[0])
            if not (0 <= val <= 65535):
                raise ValueError(f"ICMP ID {val} is out of range [0, 65535]")
        elif len(parts) == 2:
            low, high = int(parts[0]), int(parts[1])
            if not (0 <= low <= 65535 and 0 <= high <= 65535):
                raise ValueError(
                    f"ICMP ID range '{icmp_id_range}' values must each be in [0, 65535]"
                )
            if low > high:
                raise ValueError(f"ICMP ID range start {low} must be <= end {high}")
        else:
            raise ValueError(
                f"Invalid ICMP ID range format '{icmp_id_range}' "
                f"(expected 'low-high' or a single integer)"
            )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Cannot parse ICMP ID range '{icmp_id_range}': {exc}") from exc


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EAMMapping:
    """Represents an EAM mapping between IPv4 and IPv6 addresses."""
    ipv4: str
    ipv6: str

    def __hash__(self):
        return hash((self.ipv4, self.ipv6))

    def __eq__(self, other):
        if not isinstance(other, EAMMapping):
            return False
        return self.ipv4 == other.ipv4 and self.ipv6 == other.ipv6

    def __str__(self):
        return f"{self.ipv4} <-> {self.ipv6}"


@dataclass
class Pool4Entry:
    """
    Represents one atomic pool4 entry: a single protocol × IPv4 address × ID range.

    For TCP and UDP the ``id_range`` is a port range (e.g. "1-65535").
    For ICMP the ``id_range`` is an ICMP Identifier range (e.g. "0-65535").
    Jool accepts the same positional ``<range>`` argument for both; the
    semantics differ only in what the numbers represent.
    """
    protocol: str   # "tcp", "udp", or "icmp" – always stored lower-case
    address: str    # IPv4 address, CIDR, or dash-range (e.g. "192.0.2.0/24")
    id_range: str   # port range (tcp/udp) or ICMP ID range (icmp)

    def __post_init__(self):
        self.protocol = self.protocol.lower()

    def __hash__(self):
        return hash((self.protocol, self.address, self.id_range))

    def __eq__(self, other):
        if not isinstance(other, Pool4Entry):
            return False
        return (
            self.protocol == other.protocol
            and self.address == other.address
            and self.id_range == other.id_range
        )

    def __str__(self):
        label = "IDs" if self.protocol == "icmp" else "ports"
        return f"{self.protocol.upper()} {self.address} ({label} {self.id_range})"


# ---------------------------------------------------------------------------
# SIIT manager
# ---------------------------------------------------------------------------

class JoolSIITManager:
    """Manages Jool SIIT instances and EAM mappings."""

    def __init__(
        self,
        instance_name: str = "defaultnat46",
        pool6: Optional[str] = None,
        dry_run: bool = False
    ):
        """
        Initialize the SIIT manager.

        Args:
            instance_name: Name of the Jool SIIT instance.
            pool6: IPv6 pool for the instance (optional for SIIT).
            dry_run: If True, only show what would be done without making changes.
        """
        self.instance_name = instance_name
        self.pool6 = pool6
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)

    def run_command(
        self,
        cmd: List[str],
        check: bool = True,
        shell: bool = False
    ) -> subprocess.CompletedProcess:
        """
        Execute a shell command.

        Args:
            cmd: Command to execute.
            check: Whether to raise exception on non-zero exit code.
            shell: Whether to use shell execution.

        Returns:
            CompletedProcess result.
        """
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        self.logger.debug(f"Executing: {cmd_str}")

        if self.dry_run and not any(x in cmd_str for x in ['display', 'show', 'list']):
            self.logger.info(f"[DRY RUN] Would execute: {cmd_str}")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check,
                shell=shell
            )
            if result.stdout:
                self.logger.debug(f"STDOUT: {result.stdout.strip()}")
            if result.stderr:
                self.logger.debug(f"STDERR: {result.stderr.strip()}")
            return result
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {cmd_str}")
            self.logger.error(f"Exit code: {e.returncode}")
            self.logger.error(f"STDOUT: {e.stdout}")
            self.logger.error(f"STDERR: {e.stderr}")
            raise

    def instance_exists(self) -> bool:
        """Check if the Jool SIIT instance exists."""
        try:
            result = self.run_command(
                ["jool_siit", "instance", "display"],
                check=False
            )
            return self.instance_name in result.stdout
        except subprocess.CalledProcessError:
            return False

    def create_instance(self):
        """Create the Jool SIIT instance if it doesn't exist."""
        if self.instance_exists():
            self.logger.info(f"jool_siit instance '{self.instance_name}' already exists")
            return

        self.logger.info(f"Creating jool_siit instance '{self.instance_name}'")

        try:
            cmd = [
                "jool_siit", "instance", "add",
                self.instance_name,
                "--netfilter"
            ]

            if self.pool6:
                pool6_clean = self.pool6.strip().strip("'").strip('"')
                cmd.extend(["--pool6", pool6_clean])
                self.logger.info(f"Using pool6: {pool6_clean}")
                self.logger.debug(f"pool6 value: [{pool6_clean}] (type: {type(pool6_clean).__name__})")
            else:
                self.logger.info("No pool6 specified (relying on EAM only)")

            self.run_command(cmd)
            self.logger.info(f"jool_siit instance '{self.instance_name}' configured")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to create instance: {e}")
            raise

    def get_current_mappings(self) -> Set[EAMMapping]:
        """
        Retrieve current EAM mappings from Jool SIIT.

        Returns:
            Set of current EAM mappings.
        """
        self.logger.info("Retrieving current EAM mappings from Jool SIIT")

        try:
            result = self.run_command(
                ["jool_siit", "-i", self.instance_name, "eam", "display"],
                check=False
            )
        except subprocess.CalledProcessError:
            self.logger.warning("Could not retrieve EAM mappings, assuming empty")
            return set()

        mappings = set()
        lines = result.stdout.strip().split('\n')

        for line in lines:
            line = line.strip()

            # Skip empty lines, headers, and separators
            if not line or line.startswith('-') or line.startswith('=') or line.startswith('+'):
                continue
            if 'IPv4' in line or 'IPv6' in line:
                continue

            # Format can be: "ipv4_addr | ipv6_addr" or "ipv4_addr    ipv6_addr"
            if '|' in line:
                parts = [p.strip() for p in line.split('|')]
            else:
                parts = line.split()

            if len(parts) >= 2:
                ipv6 = parts[1].strip()
                ipv4 = parts[2].strip()

                if ipv4 and ipv6 and '.' in ipv4 and ':' in ipv6:
                    mappings.add(EAMMapping(ipv4, ipv6))
                    self.logger.info(f"Found mapping: {ipv4} <-> {ipv6}")

        self.logger.info(f"Found {len(mappings)} existing mappings")
        return mappings

    def add_mapping(self, mapping: EAMMapping) -> bool:
        """Add an EAM mapping to Jool SIIT."""
        self.logger.info(f"Adding mapping: {mapping}")
        try:
            self.run_command([
                "jool_siit", "-i", self.instance_name,
                "eam", "add",
                mapping.ipv4,
                mapping.ipv6
            ])
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to add mapping {mapping}: {e}")
            return False

    def remove_mapping(self, mapping: EAMMapping) -> bool:
        """Remove an EAM mapping from Jool SIIT."""
        self.logger.info(f"Removing mapping: {mapping}")
        try:
            self.run_command([
                "jool_siit", "-i", self.instance_name,
                "eam", "remove",
                mapping.ipv4,
                mapping.ipv6
            ])
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to remove mapping {mapping}: {e}")
            return False

    def load_config(self, config_path: str, auto_convert: bool = True) -> Set[EAMMapping]:
        """
        Load desired EAM mappings from YAML config file.

        Args:
            config_path: Path to YAML config file.
            auto_convert: Enable automatic IPv6 address generation from IPv4.

        Returns:
            Set of desired EAM mappings.
        """
        self.logger.info(f"Loading configuration from {config_path}")

        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)

        if not config:
            self.logger.warning("Config file is empty")
            return set()

        mappings = set()
        mapping_list = None
        default_prefix = None

        if 'eam_mappings' in config:
            mapping_list = config['eam_mappings']
            default_prefix = config.get('auto_convert_prefix', '64:ff9b::/96')
        elif 'mappings' in config:
            mapping_list = config['mappings']
            default_prefix = config.get('auto_convert_prefix', '64:ff9b::/96')
        elif isinstance(config, list):
            mapping_list = config
            default_prefix = '64:ff9b::/96'
        else:
            raise ValueError("Config must contain 'eam_mappings', 'mappings' key, or be a list")

        if not mapping_list:
            self.logger.warning("No mappings found in config")
            return set()

        for item in mapping_list:
            if isinstance(item, dict):
                ipv4 = item.get('ipv4')
                ipv6 = item.get('ipv6')

                if not ipv4 or not ipv6:
                    self.logger.warning(f"Skipping invalid mapping: {item}")
                    continue

                try:
                    if ipv6.lower() == 'auto':
                        ipv6 = f"auto:{default_prefix}"

                    ipv4_final, ipv6_final = parse_eam_mapping(ipv4, ipv6, auto_convert=auto_convert)
                    mappings.add(EAMMapping(ipv4_final, ipv6_final))

                    if ipv6.startswith('auto'):
                        self.logger.info(f"Auto-converted: {ipv4} -> {ipv4_final} <-> {ipv6_final}")
                    else:
                        self.logger.debug(f"Loaded mapping: {ipv4_final} <-> {ipv6_final}")

                except ValueError as e:
                    self.logger.error(f"Error processing mapping {ipv4} <-> {ipv6}: {e}")
                    continue
            else:
                self.logger.warning(f"Skipping invalid mapping format: {item}")

        self.logger.info(f"Loaded {len(mappings)} mappings from config")
        return mappings

    def sync_mappings(self, desired_mappings: Set[EAMMapping]) -> Tuple[int, int, int]:
        """
        Synchronize Jool EAM with desired mappings (idempotent).

        Args:
            desired_mappings: Set of desired mappings.

        Returns:
            Tuple of (added_count, removed_count, unchanged_count).
        """
        current_mappings = self.get_current_mappings()

        self.logger.debug(f"Current mappings {current_mappings}")
        self.logger.debug(f"Desired mappings {desired_mappings}")

        to_add = desired_mappings - current_mappings
        to_remove = current_mappings - desired_mappings
        unchanged = current_mappings & desired_mappings

        self.logger.info(
            f"Sync plan: {len(to_add)} to add, {len(to_remove)} to remove, {len(unchanged)} unchanged"
        )

        removed_count = 0
        for mapping in to_remove:
            if self.remove_mapping(mapping):
                removed_count += 1

        added_count = 0
        for mapping in to_add:
            if self.add_mapping(mapping):
                added_count += 1

        return added_count, removed_count, len(unchanged)

    def setup(self):
        """Complete setup: create SIIT instance if absent."""
        self.create_instance()

        self.logger.info(f"Enabling jool_siit instance '{self.instance_name}' (manually-enabled)")
        self.run_command([
            "jool_siit", "-i", self.instance_name,
            "global", "update", "manually-enabled", "true"
        ])


# ---------------------------------------------------------------------------
# NAT64 manager
# ---------------------------------------------------------------------------

class JoolNAT64Manager:
    """Manages Jool NAT64 instances, including multiple pool4 addresses."""

    def __init__(
        self,
        instance_name: str = "defaultnat64",
        pool6: str = "64:ff9b::/96",
        pool4: Optional[List[str]] = None,
        pool4_protocols: Optional[List[str]] = None,
        pool4_port_range: str = "1-65535",
        icmp_id_range: str = "0-65535",
        dry_run: bool = False
    ):
        """
        Initialize the NAT64 manager.

        Args:
            instance_name: Name of the Jool NAT64 instance.
            pool6: IPv6 pool for the instance (required for NAT64).
            pool4: List of IPv4 pool addresses/prefixes.  Every address is
                   applied to every protocol in ``pool4_protocols``.
                   e.g. ["192.0.2.0/24", "198.51.100.0/24"]
            pool4_protocols: Protocols to configure for every pool4 address.
                             Accepted values: "tcp", "udp", "icmp".
                             Defaults to ["tcp", "udp"].
            pool4_port_range: Port range for TCP and UDP entries (default "1-65535").
                              Ignored when the protocol is "icmp".
            icmp_id_range: ICMP Identifier range for ICMP pool4 entries
                           (default "0-65535").  ICMP Identifiers are 16-bit
                           unsigned integers (0-65535) used by Jool to track
                           ICMP Echo sessions instead of port numbers.  Jool
                           exposes this via the ``--icmp`` flag on pool4
                           add/remove.  Restricting the range (e.g. "1024-2047")
                           avoids ID collisions when multiple NAT64 boxes share
                           the same pool4 address.
                           Ignored when "icmp" is not in ``pool4_protocols``.
            dry_run: If True, only show what would be done without making changes.
        """
        self.instance_name = instance_name
        self.pool6 = pool6
        # Normalise pool4 to a clean list
        self.pool4: List[str] = []
        if pool4:
            for addr in pool4:
                clean = addr.strip().strip("'").strip('"')
                if clean:
                    self.pool4.append(clean)
        self.pool4_protocols: List[str] = [p.lower() for p in (pool4_protocols or ['tcp', 'udp'])]
        self.pool4_port_range = pool4_port_range
        self.icmp_id_range = icmp_id_range
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)

        # Validate ICMP ID range eagerly if ICMP is requested
        if 'icmp' in self.pool4_protocols:
            validate_icmp_id_range(self.icmp_id_range)

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def run_command(
        self,
        cmd: List[str],
        check: bool = True,
        shell: bool = False
    ) -> subprocess.CompletedProcess:
        """
        Execute a shell command.

        Args:
            cmd: Command to execute.
            check: Whether to raise exception on non-zero exit code.
            shell: Whether to use shell execution.

        Returns:
            CompletedProcess result.
        """
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        self.logger.debug(f"Executing: {cmd_str}")

        if self.dry_run and not any(x in cmd_str for x in ['display', 'show', 'list']):
            self.logger.info(f"[DRY RUN] Would execute: {cmd_str}")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check,
                shell=shell
            )
            if result.stdout:
                self.logger.debug(f"STDOUT: {result.stdout.strip()}")
            if result.stderr:
                self.logger.debug(f"STDERR: {result.stderr.strip()}")
            return result
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {cmd_str}")
            self.logger.error(f"Exit code: {e.returncode}")
            self.logger.error(f"STDOUT: {e.stdout}")
            self.logger.error(f"STDERR: {e.stderr}")
            raise

    # ------------------------------------------------------------------
    # Instance management
    # ------------------------------------------------------------------

    def instance_exists(self) -> bool:
        """Check if the Jool NAT64 instance exists."""
        try:
            result = self.run_command(
                ["jool", "instance", "display"],
                check=False
            )
            return self.instance_name in result.stdout
        except subprocess.CalledProcessError:
            return False

    def create_instance(self):
        """Create the Jool NAT64 instance if it doesn't exist."""
        if self.instance_exists():
            self.logger.info(f"jool instance '{self.instance_name}' already exists")
            return

        self.logger.info(f"Creating jool NAT64 instance '{self.instance_name}'")

        pool6_clean = self.pool6.strip().strip("'").strip('"')
        self.logger.debug(f"pool6 value: [{pool6_clean}] (type: {type(pool6_clean).__name__})")

        try:
            self.run_command([
                "jool", "instance", "add",
                self.instance_name,
                "--netfilter",
                "--pool6", pool6_clean
            ])
            self.logger.info(
                f"jool NAT64 instance '{self.instance_name}' configured with pool6: {pool6_clean}"
            )
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to create NAT64 instance: {e}")
            raise

    # ------------------------------------------------------------------
    # Pool4: desired-state derivation
    # ------------------------------------------------------------------

    def build_desired_pool4_entries(self) -> Set[Pool4Entry]:
        """
        Build the complete set of desired Pool4Entry objects from the current
        configuration (self.pool4 × self.pool4_protocols).

        Each address is combined with each protocol.  TCP/UDP entries use
        ``self.pool4_port_range``; ICMP entries use ``self.icmp_id_range``.

        Returns:
            Set of Pool4Entry representing the desired pool4 state.
        """
        desired: Set[Pool4Entry] = set()
        for address in self.pool4:
            for protocol in self.pool4_protocols:
                id_range = self.icmp_id_range if protocol == 'icmp' else self.pool4_port_range
                desired.add(Pool4Entry(protocol=protocol, address=address, id_range=id_range))
        return desired

    # ------------------------------------------------------------------
    # Pool4: read current state
    # ------------------------------------------------------------------

    def get_pool4_entries(self) -> Set[Pool4Entry]:
        """
        Retrieve current pool4 entries from the running Jool NAT64 instance.

        Jool's ``pool4 display`` output looks like::

            +------+----------+---------------+-------------+
            | Mark | Protocol | Address       | Ports       |
            +------+----------+---------------+-------------+
            |    0 | TCP      | 192.0.2.0/24  | 1-65535     |
            |    0 | UDP      | 192.0.2.0/24  | 1-65535     |
            |    0 | ICMP     | 192.0.2.0/24  | 0-65535     |
            +------+----------+---------------+-------------+

        The "Ports" column header is also used for ICMP ID ranges.

        Returns:
            Set of Pool4Entry representing the current pool4 state.
        """
        self.logger.info("Retrieving current pool4 entries from Jool NAT64")

        try:
            resulttcp = self.run_command(
                ["jool", "-i", self.instance_name, "pool4", "display", "--tcp"],
                check=False
            )
            resultudp = self.run_command(
                ["jool", "-i", self.instance_name, "pool4", "display", "--udp"],
                check=False
            )
            resulticmp = self.run_command(
                ["jool", "-i", self.instance_name, "pool4", "display", "--icmp"],
                check=False
            )
        except subprocess.CalledProcessError:
            self.logger.warning("Could not retrieve pool4 entries, assuming empty")
            return set()

        entries: Set[Pool4Entry] = set()
        lines = resulttcp.stdout.strip().split('\n') + resultudp.stdout.strip().split('\n') + resulticmp.stdout.strip().split('\n')

        for line in lines:
            line = line.strip()

            # Skip separators and header rows
            if not line or line.startswith('+') or line.startswith('-') or line.startswith('='):
                continue
            if '|' not in line:
                continue

            parts = [p.strip() for p in line.split('|') if p.strip()]
            # Expected columns: Mark | Protocol | Address | Ports/IDs
            if len(parts) < 4:
                continue

            protocol_raw = parts[1].lower()
            address_raw = parts[3]
            id_range_raw = parts[4]

            if protocol_raw not in ('tcp', 'udp', 'icmp'):
                continue
            if '.' not in address_raw:   # must look like an IPv4 address
                continue

            entry = Pool4Entry(protocol=protocol_raw, address=address_raw, id_range=id_range_raw)
            entries.add(entry)
            self.logger.debug(f"Found pool4 entry: {entry}")

        self.logger.info(f"Found {len(entries)} pool4 entries")
        return entries

    # ------------------------------------------------------------------
    # Pool4: add / remove individual entries
    # ------------------------------------------------------------------

    def add_pool4_entry(self, entry: Pool4Entry) -> bool:
        """
        Add a single Pool4Entry to the NAT64 instance.

        Jool command:
            jool -i <instance> pool4 add --<protocol> <address> <id_range>

        For ICMP, ``--icmp`` is used together with the ICMP ID range instead of
        port numbers.

        Args:
            entry: The pool4 entry to add.

        Returns:
            True if successful, False otherwise.
        """
        self.logger.info(f"Adding pool4 entry: {entry}")
        try:
            self.run_command([
                "jool", "-i", self.instance_name,
                "pool4", "add",
                f"--{entry.protocol}",
                entry.address,
                entry.id_range
            ])
            self.logger.info(f"Successfully added pool4 entry: {entry}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to add pool4 entry {entry}: {e}")
            return False

    def remove_pool4_entry(self, entry: Pool4Entry) -> bool:
        """
        Remove a single Pool4Entry from the NAT64 instance.

        Jool command:
            jool -i <instance> pool4 remove --<protocol> <address> <id_range>

        Args:
            entry: The pool4 entry to remove.

        Returns:
            True if successful, False otherwise.
        """
        self.logger.info(f"Removing pool4 entry: {entry}")
        try:
            self.run_command([
                "jool", "-i", self.instance_name,
                "pool4", "remove",
                f"--{entry.protocol}",
                entry.address,
                entry.id_range
            ])
            self.logger.info(f"Successfully removed pool4 entry: {entry}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to remove pool4 entry {entry}: {e}")
            return False

    def flush_pool4(self):
        """Flush all pool4 entries (bulk removal fallback)."""
        self.logger.info("Flushing all pool4 entries")
        try:
            self.run_command([
                "jool", "-i", self.instance_name,
                "pool4", "flush"
            ])
            self.logger.info("Successfully flushed pool4")
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to flush pool4: {e}")
            # Fall back to removing entries one by one
            for entry in self.get_pool4_entries():
                self.remove_pool4_entry(entry)

    # ------------------------------------------------------------------
    # Pool4: idempotent sync
    # ------------------------------------------------------------------

    def sync_pool4(self, desired_entries: Set[Pool4Entry]) -> Tuple[int, int, int]:
        """
        Synchronize pool4 with the desired set of entries (idempotent).

        Entries present in Jool but absent from ``desired_entries`` are removed.
        Entries in ``desired_entries`` but absent from Jool are added.
        Entries present in both are left untouched.

        Args:
            desired_entries: The complete desired pool4 state.

        Returns:
            Tuple of (added_count, removed_count, unchanged_count).
        """
        current_entries = self.get_pool4_entries()

        self.logger.debug(f"Current pool4 entries: {current_entries}")
        self.logger.debug(f"Desired pool4 entries: {desired_entries}")

        to_add = desired_entries - current_entries
        to_remove = current_entries - desired_entries
        unchanged = current_entries & desired_entries

        self.logger.info(
            f"Pool4 sync plan: {len(to_add)} to add, "
            f"{len(to_remove)} to remove, {len(unchanged)} unchanged"
        )

        removed_count = 0
        for entry in to_remove:
            if self.remove_pool4_entry(entry):
                removed_count += 1

        added_count = 0
        for entry in to_add:
            if self.add_pool4_entry(entry):
                added_count += 1

        return added_count, removed_count, len(unchanged)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def setup(self) -> Tuple[int, int, int]:
        """
        Complete setup: create instance if absent, then sync pool4 idempotently.

        Returns:
            Tuple of (pool4_added, pool4_removed, pool4_unchanged).
        """
        self.create_instance()

        desired = self.build_desired_pool4_entries()

        self.logger.info(f"Enabling jool instance '{self.instance_name}' (manually-enabled)")
        self.run_command([
            "jool", "-i", self.instance_name,
            "global", "update", "manually-enabled", "true"
        ])

        if desired:
            return self.sync_pool4(desired)
        return 0, 0, 0


# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Manage Jool SIIT/NAT64 instance and EAM/pool4 mappings (idempotent)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  JOOL_MODE              Mode: 'siit' or 'nat64' (default: siit)
  JOOL_INSTANCE_SIIT     SIIT instance name (default: defaultnat46)
  JOOL_INSTANCE_NAT64    NAT64 instance name (default: defaultnat64)
  JOOL_POOL6             IPv6 pool (default: 64:ff9b::/96 for NAT64, optional for SIIT)
  JOOL_POOL4             Comma-separated IPv4 pool addresses for NAT64
                           e.g. "192.0.2.0/24,198.51.100.0/24"
  JOOL_POOL4_PROTOCOLS   Comma-separated protocols (default: tcp,udp; also accepts icmp)
  JOOL_POOL4_PORT_RANGE  Port range for TCP/UDP entries (default: 1-65535)
  JOOL_ICMP_ID_RANGE     ICMP Identifier range for ICMP pool4 entries (default: 0-65535)
  EAM_CONFIG_FILE        Path to EAM config YAML file (SIIT mode only)

ICMP ID range:
  ICMP does not use port numbers; Jool tracks NAT64 sessions using the 16-bit
  ICMP Identifier field present in Echo Request/Reply (ping) messages.
  Including 'icmp' in --pool4-protocols creates a pool4 entry with --icmp and
  the configured ID range.  Restricting the range (e.g. "1024-2047") avoids
  Identifier collisions when multiple NAT64 appliances share the same pool4
  address.

Pool4 idempotency:
  On every run the script reads the live pool4 state from Jool, computes the
  delta against the desired state (address × protocol cartesian product), then
  adds missing entries and removes unexpected ones.  No entry is touched if it
  already matches the desired configuration.

Examples:
  # SIIT mode: Setup instance and sync EAM mappings
  %(prog)s --mode siit /etc/jool/eam_config.yaml

  # SIIT mode: Custom instance name
  %(prog)s --mode siit --instance my-siit /etc/jool/eam_config.yaml
  %(prog)s --mode siit --siit-instance my-siit /etc/jool/eam_config.yaml

  # SIIT mode: Without pool6 (EAM only)
  %(prog)s --mode siit --no-pool6 /etc/jool/eam_config.yaml

  # NAT64 mode: Setup instance only (no pool4)
  %(prog)s --mode nat64

  # NAT64 mode: Single pool4 address, TCP + UDP (classic)
  %(prog)s --mode nat64 --pool4 192.0.2.0/24

  # NAT64 mode: Multiple pool4 addresses
  %(prog)s --mode nat64 --pool4 192.0.2.0/24 --pool4 198.51.100.0/24

  # NAT64 mode: Full protocol suite including ICMP
  %(prog)s --mode nat64 --pool4 192.0.2.0/24 --pool4-protocols tcp udp icmp

  # NAT64 mode: Restricted ICMP ID range (shared pool4 address scenario)
  %(prog)s --mode nat64 --pool4 192.0.2.0/24 --pool4-protocols tcp udp icmp \\
           --icmp-id-range 1024-2047

  # NAT64 mode: Multiple pools, custom port and ICMP ID ranges
  %(prog)s --mode nat64 --pool4 192.0.2.0/24 --pool4 198.51.100.0/24 \\
           --pool4-protocols tcp udp icmp \\
           --pool4-port-range 49152-65535 --icmp-id-range 49152-65535

  # Dry run to see what would change
  %(prog)s --dry-run --mode nat64 --pool4 192.0.2.0/24 --pool4-protocols tcp udp icmp
        """
    )
    parser.add_argument(
        'config',
        nargs='?',
        help='Path to YAML configuration file for EAM mappings (required for SIIT mode, ignored for NAT64)'
    )
    parser.add_argument(
        '-m', '--mode',
        choices=['siit', 'nat64'],
        help='Jool mode: siit or nat64 (default: from JOOL_MODE or "siit")'
    )
    parser.add_argument(
        '-i', '--instance',
        help='Jool instance name (overrides mode-specific defaults)'
    )
    parser.add_argument(
        '--siit-instance',
        help='SIIT instance name (default: from JOOL_INSTANCE_SIIT or "defaultnat46")'
    )
    parser.add_argument(
        '--nat64-instance',
        help='NAT64 instance name (default: from JOOL_INSTANCE_NAT64 or "defaultnat64")'
    )
    parser.add_argument(
        '-p', '--pool6',
        help='IPv6 pool (default: from JOOL_POOL6 or "64:ff9b::/96", optional for SIIT)'
    )
    parser.add_argument(
        '--pool4',
        action='append',
        dest='pool4',
        metavar='ADDRESS',
        help=(
            'IPv4 pool address or prefix (e.g. "192.0.2.0/24"). '
            'Repeat the flag to configure multiple addresses: --pool4 A --pool4 B. '
            'Can also be set via JOOL_POOL4 as a comma-separated list.'
        )
    )
    parser.add_argument(
        '--pool4-protocols',
        nargs='+',
        choices=['tcp', 'udp', 'icmp'],
        help=(
            'Protocols for every pool4 address (default: tcp udp). '
            'Include "icmp" to translate ICMP Echo (ping) via Identifier mapping.'
        )
    )
    parser.add_argument(
        '--pool4-port-range',
        default='1-65535',
        help='Port range for pool4 TCP/UDP entries (default: 1-65535)'
    )
    parser.add_argument(
        '--icmp-id-range',
        default='0-65535',
        help=(
            'ICMP Identifier range for pool4 ICMP entries (default: 0-65535). '
            'Values must be 16-bit unsigned integers in [0, 65535]. '
            'Only applied when "icmp" is in --pool4-protocols. '
            'Can also be set via JOOL_ICMP_ID_RANGE.'
        )
    )
    parser.add_argument(
        '--no-pool6',
        action='store_true',
        help='Do not use pool6 for SIIT (EAM only mode)'
    )
    parser.add_argument(
        '-n', '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Determine mode
    mode = args.mode or os.environ.get('JOOL_MODE', 'siit')

    # ----------------------------------------------------------------
    # SIIT-specific configuration
    # ----------------------------------------------------------------
    if mode == 'siit':
        config_path = args.config or os.environ.get('EAM_CONFIG_FILE')

        if args.instance:
            instance_name = args.instance
        elif args.siit_instance:
            instance_name = args.siit_instance
        else:
            instance_name = os.environ.get('JOOL_INSTANCE_SIIT', 'defaultnat46')

        default_pool6 = os.environ.get('JOOL_POOL6')  # Optional for SIIT
        pool4: List[str] = []
        pool4_protocols: List[str] = []
        pool4_port_range = '1-65535'
        icmp_id_range = '0-65535'

    # ----------------------------------------------------------------
    # NAT64-specific configuration
    # ----------------------------------------------------------------
    else:
        config_path = None  # NAT64 doesn't use EAM config

        if args.instance:
            instance_name = args.instance
        elif args.nat64_instance:
            instance_name = args.nat64_instance
        else:
            instance_name = os.environ.get('JOOL_INSTANCE_NAT64', 'defaultnat64')

        default_pool6 = os.environ.get('JOOL_POOL6', '64:ff9b::/96')  # Required for NAT64

        # Pool4: CLI (--pool4 repeated) takes priority over env var (comma-separated)
        pool4_from_cli: List[str] = args.pool4 or []
        pool4_from_env: List[str] = [
            addr.strip().strip("'").strip('"')
            for addr in os.environ.get('JOOL_POOL4', '').split(',')
            if addr.strip()
        ]
        pool4 = pool4_from_cli if pool4_from_cli else pool4_from_env

        # Pool4 protocols
        pool4_protocols = args.pool4_protocols or []
        if not pool4_protocols:
            env_protocols = os.environ.get('JOOL_POOL4_PROTOCOLS', '')
            pool4_protocols = (
                [p.strip().lower() for p in env_protocols.split(',') if p.strip()]
                if env_protocols else ['tcp', 'udp']
            )

        # Validate protocol names coming from env var (argparse handles CLI)
        valid_protocols = {'tcp', 'udp', 'icmp'}
        for proto in pool4_protocols:
            if proto not in valid_protocols:
                logger.error(
                    f"Invalid protocol '{proto}'. Must be one of: {', '.join(sorted(valid_protocols))}"
                )
                sys.exit(1)

        # Port range for TCP/UDP
        pool4_port_range = args.pool4_port_range or os.environ.get('JOOL_POOL4_PORT_RANGE', '1-65535')

        # ICMP ID range
        icmp_id_range = args.icmp_id_range or os.environ.get('JOOL_ICMP_ID_RANGE', '0-65535')
        if 'icmp' in pool4_protocols:
            try:
                validate_icmp_id_range(icmp_id_range)
            except ValueError as e:
                logger.error(f"Invalid ICMP ID range '{icmp_id_range}': {e}")
                sys.exit(1)

    # ----------------------------------------------------------------
    # Pool6
    # ----------------------------------------------------------------
    if args.no_pool6:
        pool6 = None
    else:
        pool6 = args.pool6 or default_pool6
        if pool6:
            pool6 = pool6.strip().strip("'").strip('"')

    # ----------------------------------------------------------------
    # Validate required parameters
    # ----------------------------------------------------------------
    if mode == 'siit' and not config_path:
        logger.error("SIIT mode requires a configuration file. Use argument or EAM_CONFIG_FILE env var.")
        sys.exit(1)

    # ----------------------------------------------------------------
    # Execute
    # ----------------------------------------------------------------
    try:
        logger.info("=" * 60)
        logger.info(f"Jool {mode.upper()} Manager")
        logger.info(f"Mode:     {mode.upper()}")
        logger.info(f"Instance: {instance_name}")
        logger.info(f"Pool6:    {pool6 or 'None (EAM only)'}")
        if mode == 'nat64':
            if pool4:
                logger.info(f"Pool4:    {', '.join(pool4)}")
                logger.info(f"Protocols:{' ' + ', '.join(pool4_protocols)}")
                if any(p in pool4_protocols for p in ('tcp', 'udp')):
                    logger.info(f"Port range:    {pool4_port_range}")
                if 'icmp' in pool4_protocols:
                    logger.info(f"ICMP ID range: {icmp_id_range}")
            else:
                logger.info("Pool4:    not configured")
        if config_path:
            logger.info(f"Config:   {config_path}")
        if args.dry_run:
            logger.info("*** DRY RUN – no changes will be made ***")
        logger.info("=" * 60)

        # ---- SIIT ----
        if mode == 'siit':
            manager = JoolSIITManager(
                instance_name=instance_name,
                pool6=pool6,
                dry_run=args.dry_run
            )
            manager.setup()

            desired_mappings = manager.load_config(config_path)
            added, removed, unchanged = manager.sync_mappings(desired_mappings)

            logger.info("=" * 60)
            logger.info("EAM synchronization complete!")
            logger.info(f"  Added:     {added}")
            logger.info(f"  Removed:   {removed}")
            logger.info(f"  Unchanged: {unchanged}")
            logger.info(f"  Total:     {added + unchanged}")
            logger.info("=" * 60)

        # ---- NAT64 ----
        else:
            if not pool6:
                logger.error("NAT64 mode requires pool6 to be specified")
                sys.exit(1)

            manager = JoolNAT64Manager(
                instance_name=instance_name,
                pool6=pool6,
                pool4=pool4,
                pool4_protocols=pool4_protocols,
                pool4_port_range=pool4_port_range,
                icmp_id_range=icmp_id_range,
                dry_run=args.dry_run
            )

            p4_added, p4_removed, p4_unchanged = manager.setup()

            logger.info("=" * 60)
            logger.info("NAT64 instance setup complete!")
            if pool4:
                logger.info("Pool4 synchronization:")
                logger.info(f"  Added:     {p4_added}")
                logger.info(f"  Removed:   {p4_removed}")
                logger.info(f"  Unchanged: {p4_unchanged}")
                logger.info(f"  Total:     {p4_added + p4_unchanged}")
            logger.info("=" * 60)

        if args.dry_run:
            logger.info("DRY RUN mode – no changes were made")

        sys.exit(0)

    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
