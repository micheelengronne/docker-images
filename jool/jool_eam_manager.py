#!/usr/bin/env python3
"""
Jool SIIT/NAT64 EAM (Explicit Address Mapping) Manager

This script manages Jool SIIT and NAT64 instances and IPv4-IPv6 EAM mappings in an idempotent manner.

Features:
- Creates Jool SIIT or NAT64 instance if not exists
- Manages EAM mappings from YAML configuration (SIIT mode only)
- Idempotent: removes mappings not in config, adds missing ones
- Supports both SIIT and NAT64 modes
- Optional pool6 for SIIT (can work with EAM only)
- Supports multiple pool4 entries with idempotent sync (NAT64)
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


@dataclass
class EAMMapping:
    """Represents an EAM mapping between IPv4 and IPv6 addresses"""
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
    """Represents a pool4 entry with address, protocols, and port range"""
    address: str
    protocols: List[str]
    port_range: str = "1-65535"

    def __hash__(self):
        return hash((self.address, tuple(sorted(self.protocols)), self.port_range))

    def __eq__(self, other):
        if not isinstance(other, Pool4Entry):
            return False
        return (self.address == other.address and
                set(self.protocols) == set(other.protocols) and
                self.port_range == other.port_range)

    def __str__(self):
        return f"{self.address} ({', '.join(self.protocols)}) ports {self.port_range}"


class JoolSIITManager:
    """Manages Jool SIIT instances and EAM mappings"""

    def __init__(
        self,
        instance_name: str = "defaultnat46",
        pool6: Optional[str] = None,
        dry_run: bool = False
    ):
        """
        Initialize the SIIT manager

        Args:
            instance_name: Name of the Jool SIIT instance
            pool6: IPv6 pool for the instance (optional for SIIT)
            dry_run: If True, only show what would be done without making changes
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
        Execute a shell command

        Args:
            cmd: Command to execute
            check: Whether to raise exception on non-zero exit code
            shell: Whether to use shell execution

        Returns:
            CompletedProcess result
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
        """
        Check if the Jool SIIT instance exists

        Returns:
            True if instance exists, False otherwise
        """
        try:
            result = self.run_command(
                ["jool_siit", "instance", "display"],
                check=False
            )
            return self.instance_name in result.stdout
        except subprocess.CalledProcessError:
            return False

    def create_instance(self):
        """Create the Jool SIIT instance if it doesn't exist"""
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

            # Add pool6 only if specified
            if self.pool6:
                # Strip any surrounding quotes
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
        Retrieve current EAM mappings from Jool SIIT

        Returns:
            Set of current EAM mappings
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

        # Parse output - Jool EAM display format varies, handle multiple formats
        for line in lines:
            line = line.strip()

            # Skip empty lines, headers, and separators
            if not line or line.startswith('-') or line.startswith('=') or line.startswith('+'):
                continue
            if 'IPv4' in line or 'IPv6' in line:
                continue

            # Try to parse mapping line
            # Format can be: "ipv4_addr | ipv6_addr" or "ipv4_addr    ipv6_addr"
            if '|' in line:
                parts = [p.strip() for p in line.split('|')]
            else:
                parts = line.split()

            if len(parts) >= 2:
                ipv6 = parts[1].strip()
                ipv4 = parts[2].strip()

                # Validate addresses have content and look valid
                if ipv4 and ipv6 and '.' in ipv4 and ':' in ipv6:
                    mappings.add(EAMMapping(ipv4, ipv6))
                    self.logger.info(f"Found mapping: {ipv4} <-> {ipv6}")

        self.logger.info(f"Found {len(mappings)} existing mappings")
        return mappings

    def add_mapping(self, mapping: EAMMapping) -> bool:
        """
        Add an EAM mapping to Jool SIIT

        Args:
            mapping: The mapping to add

        Returns:
            True if successful, False otherwise
        """
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
        """
        Remove an EAM mapping from Jool SIIT

        Args:
            mapping: The mapping to remove

        Returns:
            True if successful, False otherwise
        """
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
        Load desired mappings from YAML config file

        Args:
            config_path: Path to YAML config file
            auto_convert: Enable automatic IPv6 address generation from IPv4

        Returns:
            Set of desired EAM mappings
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

        # Support multiple config formats
        mapping_list = None
        default_prefix = None

        if 'eam_mappings' in config:
            mapping_list = config['eam_mappings']
            # Check for global auto_convert_prefix
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

                # Handle auto-conversion
                try:
                    # If ipv6 is "auto", use the default prefix
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
        Synchronize Jool EAM with desired mappings (idempotent)

        Args:
            desired_mappings: Set of desired mappings

        Returns:
            Tuple of (added_count, removed_count, unchanged_count)
        """
        current_mappings = self.get_current_mappings()

        self.logger.debug(f"Current mappings {current_mappings}")
        self.logger.debug(f"Desired mappings {desired_mappings}")

        # Calculate differences
        to_add = desired_mappings - current_mappings
        to_remove = current_mappings - desired_mappings
        unchanged = current_mappings & desired_mappings

        self.logger.info(f"Sync plan: {len(to_add)} to add, {len(to_remove)} to remove, {len(unchanged)} unchanged")

        # Remove unwanted mappings first
        removed_count = 0
        for mapping in to_remove:
            if self.remove_mapping(mapping):
                removed_count += 1

        # Add new mappings
        added_count = 0
        for mapping in to_add:
            if self.add_mapping(mapping):
                added_count += 1

        return added_count, removed_count, len(unchanged)

    def setup(self):
        """
        Complete setup process
        """

        # Create SIIT instance
        self.create_instance()


class JoolNAT64Manager:
    """Manages Jool NAT64 instances"""

    def __init__(
        self,
        instance_name: str = "defaultnat64",
        pool6: str = "64:ff9b::/96",
        pool4_entries: Optional[List[Pool4Entry]] = None,
        dry_run: bool = False
    ):
        """
        Initialize the NAT64 manager

        Args:
            instance_name: Name of the Jool NAT64 instance
            pool6: IPv6 pool for the instance (required for NAT64)
            pool4_entries: List of Pool4Entry objects (optional)
            dry_run: If True, only show what would be done without making changes
        """
        self.instance_name = instance_name
        self.pool6 = pool6
        self.pool4_entries = pool4_entries or []
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)

    def run_command(
        self,
        cmd: List[str],
        check: bool = True,
        shell: bool = False
    ) -> subprocess.CompletedProcess:
        """
        Execute a shell command

        Args:
            cmd: Command to execute
            check: Whether to raise exception on non-zero exit code
            shell: Whether to use shell execution

        Returns:
            CompletedProcess result
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
        """
        Check if the Jool NAT64 instance exists

        Returns:
            True if instance exists, False otherwise
        """
        try:
            result = self.run_command(
                ["jool", "instance", "display"],
                check=False
            )
            return self.instance_name in result.stdout
        except subprocess.CalledProcessError:
            return False

    def create_instance(self):
        """Create the Jool NAT64 instance if it doesn't exist"""
        if self.instance_exists():
            self.logger.info(f"jool instance '{self.instance_name}' already exists")
            # Sync pool4 entries even if instance exists
            if self.pool4_entries:
                added, removed, unchanged = self.sync_pool4(self.pool4_entries)
                self.logger.info(f"Pool4 sync: {added} added, {removed} removed, {unchanged} unchanged")
            return

        self.logger.info(f"Creating jool NAT64 instance '{self.instance_name}'")

        # Strip any surrounding quotes from pool6
        pool6_clean = self.pool6.strip().strip("'").strip('"')
        self.logger.debug(f"pool6 value: [{pool6_clean}] (type: {type(pool6_clean).__name__})")

        try:
            self.run_command([
                "jool", "instance", "add",
                self.instance_name,
                "--netfilter",
                "--pool6", pool6_clean
            ])
            self.logger.info(f"jool NAT64 instance '{self.instance_name}' configured with pool6: {pool6_clean}")

            # Sync pool4 entries if specified
            if self.pool4_entries:
                added, removed, unchanged = self.sync_pool4(self.pool4_entries)
                self.logger.info(f"Pool4 sync: {added} added, {removed} removed, {unchanged} unchanged")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to create NAT64 instance: {e}")
            raise

    def add_pool4_entry(self, entry: Pool4Entry) -> bool:
        """
        Add a pool4 entry to the NAT64 instance

        Args:
            entry: Pool4Entry to add

        Returns:
            True if all protocols added successfully, False otherwise
        """
        address_clean = entry.address.strip().strip("'").strip('"')
        self.logger.info(f"Adding pool4 entry: {entry}")

        success = True
        # Add pool4 for each protocol
        for protocol in entry.protocols:
            try:
                cmd = [
                    "jool", "-i", self.instance_name,
                    "pool4", "add"
                ]

                # Add protocol flag
                if protocol.lower() == 'tcp':
                    cmd.extend(["--tcp", address_clean, entry.port_range])
                elif protocol.lower() == 'udp':
                    cmd.extend(["--udp", address_clean, entry.port_range])
                elif protocol.lower() == 'icmp':
                    cmd.extend(["--icmp", address_clean])
                else:
                    self.logger.warning(f"Unknown protocol: {protocol}, skipping")
                    continue

                self.run_command(cmd)
                self.logger.debug(f"Successfully added pool4 for {protocol.upper()}: {address_clean}")

            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to add pool4 for {protocol.upper()} {address_clean}: {e}")
                success = False

        return success

    def get_pool4_entries(self) -> Dict[str, List[Dict[str, str]]]:
        """
        Retrieve current pool4 entries from Jool NAT64

        Returns:
            Dict mapping addresses to list of protocol/port entries
            Example: {"192.0.2.1": [{"protocol": "tcp", "ports": "1-65535"}, ...]}
        """
        self.logger.info("Retrieving current pool4 entries from Jool NAT64")

        try:
            result = self.run_command(
                ["jool", "-i", self.instance_name, "pool4", "display", "--tcp"],
                check=False
            )
            result += self.run_command(
                ["jool", "-i", self.instance_name, "pool4", "display", "--udp"],
                check=False
            )
            result += self.run_command(
                ["jool", "-i", self.instance_name, "pool4", "display", "--icmp"],
                check=False
            )
        except subprocess.CalledProcessError:
            self.logger.warning("Could not retrieve pool4 entries, assuming empty")
            return {}

        entries = {}
        lines = result.stdout.strip().split('\n')

        for line in lines:
            line = line.strip()

            # Skip empty lines, headers, and separators
            if not line or line.startswith('-') or line.startswith('=') or line.startswith('+'):
                continue
            if 'Protocol' in line or 'Address' in line or 'Ports' in line or 'Mark' in line:
                continue

            # Parse line
            parts = line.split()
            if len(parts) >= 2:
                protocol = parts[1].lower()
                address = parts[3]
                ports = parts[4] if len(parts) >= 4 else ""

                # Skip non-TCP/UDP/ICMP protocols
                if protocol not in ['tcp', 'udp', 'icmp']:
                    continue

                if address not in entries:
                    entries[address] = []

                entries[address].append({
                    "protocol": protocol,
                    "ports": ports
                })
                self.logger.debug(f"Found pool4 entry: {protocol.upper()} {address} {ports}")

        self.logger.info(f"Found {len(entries)} pool4 addresses with {sum(len(v) for v in entries.values())} total entries")
        return entries

    def remove_pool4_entry(self, address: str, protocol: str) -> bool:
        """
        Remove a specific pool4 entry from the NAT64 instance

        Args:
            address: IPv4 address to remove
            protocol: Protocol to remove (tcp, udp, icmp)

        Returns:
            True if successful, False otherwise
        """
        self.logger.info(f"Removing pool4 entry: {protocol.upper()} {address}")

        try:
            cmd = ["jool", "-i", self.instance_name, "pool4", "remove"]

            if protocol.lower() == 'tcp':
                cmd.extend(["--tcp", address])
            elif protocol.lower() == 'udp':
                cmd.extend(["--udp", address])
            elif protocol.lower() == 'icmp':
                cmd.extend(["--icmp", address])
            else:
                self.logger.warning(f"Unknown protocol: {protocol}")
                return False

            self.run_command(cmd)
            self.logger.debug(f"Successfully removed pool4 entry: {protocol.upper()} {address}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to remove pool4 {protocol.upper()} {address}: {e}")
            return False

    def sync_pool4(self, desired_entries: List[Pool4Entry]) -> Tuple[int, int, int]:
        """
        Synchronize pool4 entries with desired state (idempotent)

        Args:
            desired_entries: List of desired Pool4Entry objects

        Returns:
            Tuple of (added_count, removed_count, unchanged_count)
        """
        self.logger.info("Synchronizing pool4 entries")

        # Get current entries
        current_entries_dict = self.get_pool4_entries()

        # Build desired state map
        desired_map = {}
        for entry in desired_entries:
            addr = entry.address.strip().strip("'").strip('"')
            if addr not in desired_map:
                desired_map[addr] = []
            for proto in entry.protocols:
                desired_map[addr].append({
                    "protocol": proto.lower(),
                    "ports": entry.port_range
                })

        self.logger.debug(f"Current pool4 state: {current_entries_dict}")
        self.logger.debug(f"Desired pool4 state: {desired_map}")

        added_count = 0
        removed_count = 0
        unchanged_count = 0

        # Remove entries that shouldn't exist
        for addr, current_protos in current_entries_dict.items():
            desired_protos = desired_map.get(addr, [])

            for current_proto_entry in current_protos:
                current_proto = current_proto_entry["protocol"]
                current_ports = current_proto_entry["ports"]

                # Check if this protocol/port combo should exist
                should_exist = False
                for desired_proto_entry in desired_protos:
                    if (desired_proto_entry["protocol"] == current_proto and
                        desired_proto_entry["ports"] == current_ports):
                        should_exist = True
                        break

                if not should_exist:
                    if self.remove_pool4_entry(addr, current_proto):
                        removed_count += 1

        # Add missing entries
        for addr, desired_protos in desired_map.items():
            current_protos = current_entries_dict.get(addr, [])

            for desired_proto_entry in desired_protos:
                desired_proto = desired_proto_entry["protocol"]
                desired_ports = desired_proto_entry["ports"]

                # Check if this protocol/port combo already exists
                already_exists = False
                for current_proto_entry in current_protos:
                    if (current_proto_entry["protocol"] == desired_proto and
                        current_proto_entry["ports"] == desired_ports):
                        already_exists = True
                        unchanged_count += 1
                        break

                if not already_exists:
                    # Create a Pool4Entry for just this protocol
                    entry = Pool4Entry(
                        address=addr,
                        protocols=[desired_proto],
                        port_range=desired_ports
                    )
                    if self.add_pool4_entry(entry):
                        added_count += 1

        self.logger.info(f"Pool4 sync complete: {added_count} added, {removed_count} removed, {unchanged_count} unchanged")
        return added_count, removed_count, unchanged_count

    def flush_pool4(self):
        """Flush all pool4 entries"""
        self.logger.info("Flushing all pool4 entries")

        try:
            self.run_command([
                "jool", "-i", self.instance_name,
                "pool4", "flush"
            ])
            self.logger.info("Successfully flushed pool4")
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to flush pool4: {e}")
            # Try to remove entries individually
            entries_dict = self.get_pool4_entries()
            for addr, protos in entries_dict.items():
                for proto_entry in protos:
                    self.remove_pool4_entry(addr, proto_entry["protocol"])

    def setup(self):
        """
        Complete setup process
        """
        # Create NAT64 instance (and sync pool4)
        self.create_instance()


def setup_logging(verbose: bool = False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_pool4_entries(
    pool4_list: List[str],
    protocols: Optional[List[str]] = None,
    port_range: str = "1-65535"
) -> List[Pool4Entry]:
    """
    Parse pool4 command-line arguments into Pool4Entry objects

    Args:
        pool4_list: List of pool4 addresses
        protocols: Default protocols to use (default: ['tcp', 'udp'])
        port_range: Default port range (default: "1-65535")

    Returns:
        List of Pool4Entry objects
    """
    if not protocols:
        protocols = ['tcp', 'udp']

    entries = []
    for pool4_str in pool4_list:
        # Support format: "address" or "address:proto1,proto2" or "address:proto1,proto2:ports"
        parts = pool4_str.split(':')
        address = parts[0].strip().strip("'").strip('"')

        entry_protocols = protocols
        entry_port_range = port_range

        if len(parts) >= 2:
            # Protocols specified
            entry_protocols = [p.strip().lower() for p in parts[1].split(',')]

        if len(parts) >= 3:
            # Port range specified
            entry_port_range = parts[2].strip()

        entries.append(Pool4Entry(
            address=address,
            protocols=entry_protocols,
            port_range=entry_port_range
        ))

    return entries


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Manage Jool SIIT/NAT64 instance and EAM mappings from YAML config (idempotent)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  JOOL_MODE              Mode: 'siit' or 'nat64' (default: siit)
  JOOL_INSTANCE_SIIT     SIIT instance name (default: defaultnat46)
  JOOL_INSTANCE_NAT64    NAT64 instance name (default: defaultnat64)
  JOOL_POOL6             IPv6 pool (default: 64:ff9b::/96 for NAT64, optional for SIIT)
  JOOL_POOL4             Comma-separated IPv4 pools for NAT64 (e.g., "192.0.2.0/24,203.0.113.1")
  JOOL_POOL4_PROTOCOLS   Comma-separated protocols (default: tcp,udp)
  JOOL_POOL4_PORT_RANGE  Port range for TCP/UDP (default: 1-65535)
  EAM_CONFIG_FILE        Path to EAM config YAML file (only for SIIT mode)

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

  # NAT64 mode: Custom instance name and pool6
  %(prog)s --mode nat64 --instance my-nat64 --pool6 2001:db8:64::/96
  %(prog)s --mode nat64 --nat64-instance my-nat64 --pool6 2001:db8:64::/96

  # NAT64 mode: With single pool4
  %(prog)s --mode nat64 --pool4 "192.0.2.0/24"

  # NAT64 mode: With multiple pool4 entries
  %(prog)s --mode nat64 --pool4 "192.0.2.0/24" --pool4 "203.0.113.1"

  # NAT64 mode: Pool4 with specific protocols per entry
  %(prog)s --mode nat64 --pool4 "192.0.2.0/24:tcp,udp" --pool4 "203.0.113.1:tcp"

  # NAT64 mode: Pool4 with custom port ranges
  %(prog)s --mode nat64 --pool4 "192.0.2.0/24:tcp,udp:49152-65535"

  # NAT64 mode: From environment variable (comma-separated)
  JOOL_POOL4="192.0.2.0/24,203.0.113.1" %(prog)s --mode nat64

  # Dry run to see what would change
  %(prog)s --dry-run --mode siit /etc/jool/eam_config.yaml
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
        help='IPv4 pool for NAT64 (can be specified multiple times). Format: "address" or "address:protocols" or "address:protocols:ports"'
    )
    parser.add_argument(
        '--pool4-protocols',
        nargs='+',
        choices=['tcp', 'udp', 'icmp'],
        help='Default protocols for pool4 entries (default: tcp udp)'
    )
    parser.add_argument(
        '--pool4-port-range',
        default='1-65535',
        help='Default port range for pool4 TCP/UDP (default: 1-65535)'
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

    # Get configuration from args or environment
    if mode == 'siit':
        config_path = args.config or os.environ.get('EAM_CONFIG_FILE')

        # Instance name priority: --instance > --siit-instance > JOOL_INSTANCE_SIIT > default
        if args.instance:
            instance_name = args.instance
        elif args.siit_instance:
            instance_name = args.siit_instance
        else:
            instance_name = os.environ.get('JOOL_INSTANCE_SIIT', 'defaultnat46')

        default_pool6 = os.environ.get('JOOL_POOL6')  # Optional for SIIT
        pool4_entries = []  # SIIT doesn't use pool4
    else:  # nat64
        config_path = None  # NAT64 doesn't use EAM config

        # Instance name priority: --instance > --nat64-instance > JOOL_INSTANCE_NAT64 > default
        if args.instance:
            instance_name = args.instance
        elif args.nat64_instance:
            instance_name = args.nat64_instance
        else:
            instance_name = os.environ.get('JOOL_INSTANCE_NAT64', 'defaultnat64')

        default_pool6 = os.environ.get('JOOL_POOL6', '64:ff9b::/96')  # Required for NAT64

        # Pool4 for NAT64 - support multiple entries
        pool4_list = args.pool4 or []

        # Also check environment variable (comma-separated)
        env_pool4 = os.environ.get('JOOL_POOL4')
        if env_pool4 and not pool4_list:
            pool4_list = [p.strip() for p in env_pool4.split(',') if p.strip()]

        # Pool4 protocols (default: tcp, udp)
        pool4_protocols = args.pool4_protocols
        if not pool4_protocols:
            # Check environment variable
            env_protocols = os.environ.get('JOOL_POOL4_PROTOCOLS')
            if env_protocols:
                pool4_protocols = [p.strip().lower() for p in env_protocols.split(',')]
            else:
                pool4_protocols = ['tcp', 'udp']

        # Pool4 port range
        pool4_port_range = args.pool4_port_range or os.environ.get('JOOL_POOL4_PORT_RANGE', '1-65535')

        # Parse pool4 entries
        pool4_entries = parse_pool4_entries(pool4_list, pool4_protocols, pool4_port_range)

    # Handle pool6
    if args.no_pool6:
        pool6 = None
    else:
        pool6 = args.pool6 or default_pool6
        # Strip any surrounding quotes that might have been added accidentally
        if pool6:
            pool6 = pool6.strip().strip("'").strip('"')

    # Validate config for SIIT mode
    if mode == 'siit' and not config_path:
        logger.error("SIIT mode requires a configuration file. Use argument or EAM_CONFIG_FILE env var.")
        sys.exit(1)

    try:
        logger.info("=" * 60)
        logger.info(f"Jool {mode.upper()} Manager")
        logger.info(f"Mode: {mode.upper()}")
        logger.info(f"Instance: {instance_name}")
        if pool6:
            logger.info(f"Pool6: {pool6}")
        else:
            logger.info("Pool6: None (EAM only)")
        if mode == 'nat64' and pool4_entries:
            logger.info(f"Pool4 entries: {len(pool4_entries)}")
            for entry in pool4_entries:
                logger.info(f"  - {entry}")
        if config_path:
            logger.info(f"Config: {config_path}")
        if args.dry_run:
            logger.info("Mode: DRY RUN")
        logger.info("=" * 60)

        if mode == 'siit':
            # SIIT mode with EAM management
            manager = JoolSIITManager(
                instance_name=instance_name,
                pool6=pool6,
                dry_run=args.dry_run
            )

            # Setup instance
            manager.setup()

            # Load desired mappings from config
            desired_mappings = manager.load_config(config_path)

            # Sync mappings (idempotent)
            added, removed, unchanged = manager.sync_mappings(desired_mappings)

            # Summary
            logger.info("=" * 60)
            logger.info("Synchronization complete!")
            logger.info(f"  Added:     {added}")
            logger.info(f"  Removed:   {removed}")
            logger.info(f"  Unchanged: {unchanged}")
            logger.info(f"  Total:     {added + unchanged}")
            logger.info("=" * 60)

        else:  # nat64
            # NAT64 mode (no EAM)
            if not pool6:
                logger.error("NAT64 mode requires pool6 to be specified")
                sys.exit(1)

            manager = JoolNAT64Manager(
                instance_name=instance_name,
                pool6=pool6,
                pool4_entries=pool4_entries,
                dry_run=args.dry_run
            )

            # Setup instance (includes pool4 sync)
            manager.setup()

            logger.info("=" * 60)
            logger.info("NAT64 instance setup complete!")
            if pool4_entries:
                logger.info(f"Pool4 entries configured: {len(pool4_entries)}")
            logger.info("=" * 60)

        if args.dry_run:
            logger.info("DRY RUN mode - no changes were made")

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
