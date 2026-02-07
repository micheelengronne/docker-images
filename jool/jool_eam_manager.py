#!/usr/bin/env python3
"""
Jool SIIT/NAT64 EAM (Explicit Address Mapping) Manager

This script manages Jool SIIT and NAT64 instances and IPv4-IPv6 EAM mappings in an idempotent manner.
It is designed as a Python replacement for the bash entrypoint.sh script.

Features:
- Creates Jool SIIT or NAT64 instance if not exists
- Manages EAM mappings from YAML configuration (SIIT mode only)
- Idempotent: removes mappings not in config, adds missing ones
- Supports both SIIT and NAT64 modes
- Optional pool6 for SIIT (can work with EAM only)
"""

import subprocess
import sys
import yaml
import logging
import os
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path


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
                cmd.extend(["--pool6", self.pool6])
                self.logger.info(f"Using pool6: {self.pool6}")
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

    def load_config(self, config_path: str) -> Set[EAMMapping]:
        """
        Load desired mappings from YAML config file

        Args:
            config_path: Path to YAML config file

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

        if 'eam_mappings' in config:
            mapping_list = config['eam_mappings']
        elif 'mappings' in config:
            mapping_list = config['mappings']
        elif isinstance(config, list):
            mapping_list = config
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

                mappings.add(EAMMapping(ipv4, ipv6))
                self.logger.debug(f"Loaded mapping: {ipv4} <-> {ipv6}")
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
        dry_run: bool = False
    ):
        """
        Initialize the NAT64 manager

        Args:
            instance_name: Name of the Jool NAT64 instance
            pool6: IPv6 pool for the instance (required for NAT64)
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
            return

        self.logger.info(f"Creating jool NAT64 instance '{self.instance_name}'")

        try:
            self.run_command([
                "jool", "instance", "add",
                self.instance_name,
                "--netfilter",
                "--pool6", self.pool6
            ])
            self.logger.info(f"jool NAT64 instance '{self.instance_name}' configured with pool6: {self.pool6}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to create NAT64 instance: {e}")
            raise

    def setup(self):
        """
        Complete setup process
        """
        # Create NAT64 instance
        self.create_instance()


def setup_logging(verbose: bool = False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Manage Jool SIIT/NAT64 instance and EAM mappings from YAML config (idempotent)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  JOOL_MODE            Mode: 'siit' or 'nat64' (default: siit)
  JOOL_INSTANCE_SIIT   SIIT instance name (default: defaultnat46)
  JOOL_INSTANCE_NAT64  NAT64 instance name (default: defaultnat64)
  JOOL_POOL6           IPv6 pool (default: 64:ff9b::/96 for NAT64, optional for SIIT)
  EAM_CONFIG_FILE      Path to EAM config YAML file (only for SIIT mode)

Examples:
  # SIIT mode: Setup instance and sync EAM mappings
  %(prog)s --mode siit /etc/jool/eam_config.yaml

  # SIIT mode: Custom instance name
  %(prog)s --mode siit --instance my-siit /etc/jool/eam_config.yaml
  %(prog)s --mode siit --siit-instance my-siit /etc/jool/eam_config.yaml

  # SIIT mode: Without pool6 (EAM only)
  %(prog)s --mode siit --no-pool6 /etc/jool/eam_config.yaml

  # NAT64 mode: Setup instance only (no EAM)
  %(prog)s --mode nat64

  # NAT64 mode: Custom instance name and pool6
  %(prog)s --mode nat64 --instance my-nat64 --pool6 2001:db8:64::/96
  %(prog)s --mode nat64 --nat64-instance my-nat64 --pool6 2001:db8:64::/96

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

    # Handle pool6
    if args.no_pool6:
        pool6 = None
    else:
        pool6 = args.pool6 or default_pool6

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
                dry_run=args.dry_run
            )

            # Setup instance
            manager.setup()

            logger.info("=" * 60)
            logger.info("NAT64 instance setup complete!")
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
