#!/usr/bin/env python3
"""
bwenv - Bitwarden Environment Variable Processor

A cross-platform tool to replace environment variables containing Bitwarden secret references
with actual secret values using the Bitwarden CLI.

Usage:
    bwenv run [--no-sync] <command> [args...]
    bwenv read [--no-sync] <uri>

Examples:
    bwenv run sh
    bwenv read op://Employee/example/secret
    bwenv run --no-sync python app.py
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


def setup_logging(debug: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(
        level=level,
        format='[%(levelname)s %(asctime)s] %(message)s',
        datefmt='%H:%M:%S',
        stream=sys.stderr
    )


def debug_print(*args):
    """Print debug messages when debug mode is enabled - kept for compatibility"""
    logging.debug(' '.join(str(arg) for arg in args))


class BWEnvError(Exception):
    """Base exception for bwenv errors."""
    pass


class URIParser:
    """Parser for op:// URIs in the format op://vaultname/item/keyname"""
    
    URI_PATTERN = re.compile(r'^op://([^/]+)/([^/]+)/(.+)$')
    
    @classmethod
    def parse_uri(cls, uri: str) -> Optional[Tuple[str, str, str]]:
        """
        Parse a URI in the format op://vaultname/item/keyname
        
        Returns:
            Tuple of (vaultname, item, keyname) or None if invalid
        """
        match = cls.URI_PATTERN.match(uri)
        if not match:
            return None
        vault, item, keyname = match.groups()
        return (vault, item, keyname)
    
    @classmethod
    def is_op_uri(cls, value: str) -> bool:
        """Check if a string is a valid op:// URI"""
        return cls.parse_uri(value) is not None


class BitwardenClient:
    """Client for interacting with Bitwarden CLI"""
    
    def __init__(self, no_sync: bool = False):
        self.sync = not no_sync
        self._items_cache = None
    
    def _run_bw_command(self, args: List[str]) -> str:
        """Run a Bitwarden CLI command and return stdout"""
        command = ['bw'] + args
        logging.debug(f"Running Bitwarden CLI command: {' '.join(command)}")
        logging.debug(f"Command arguments: {args}")
        logging.debug(f"Full command: {command}")
        
        # Check if we need authentication for this command
        needs_auth = any(cmd in args for cmd in ['sync', 'list', 'get'])
        logging.debug(f"Command needs authentication: {needs_auth}")
        
        bw_session = os.environ.get('BW_SESSION')
        logging.debug(f"BW_SESSION present: {bool(bw_session)}")
        if bw_session:
            logging.debug(f"BW_SESSION length: {len(bw_session)} characters")
        
        if needs_auth and not bw_session:
            logging.debug("No BW_SESSION found, checking if user is logged in...")
            # First check if user is logged in but not unlocked
            try:
                status_result = subprocess.run(
                    ['bw', 'status'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                # Handle empty response from mocked tests or real empty responses
                status_output = status_result.stdout.strip()
                logging.debug(f"Status command output: {status_output}")
                if not status_output:
                    logging.debug("Empty status response, will let command fail naturally if not authenticated")
                else:
                    try:
                        status_data = json.loads(status_output)
                        logging.debug(f"Parsed status data: {status_data}")
                        if status_data.get('status') == 'locked':
                            # Vault is locked, need to unlock interactively
                            logging.debug("Vault is locked, prompting for unlock")
                            print("Bitwarden vault is locked. Please enter your master password to unlock:", file=sys.stderr)
                            unlock_result = subprocess.run(
                                ['bw', 'unlock', '--raw'],
                                stdin=sys.stdin,
                                stdout=subprocess.PIPE,
                                stderr=sys.stderr,
                                text=True,
                                check=True
                            )
                            session_token = unlock_result.stdout.strip()
                            os.environ['BW_SESSION'] = session_token
                            logging.debug("Successfully unlocked vault and set BW_SESSION")
                        elif status_data.get('status') == 'unauthenticated':
                            logging.debug("User is not authenticated")
                            raise BWEnvError("You are not logged in")
                    except (json.JSONDecodeError, TypeError):
                        logging.debug("Failed to parse JSON status response, will let command fail naturally if not authenticated")
            except subprocess.CalledProcessError as e:
                stderr = e.stderr or ""
                if "not logged in" in stderr or "You are not logged in" in stderr:
                    raise BWEnvError("You are not logged in")
                logging.debug(f"Status check failed, will let command fail naturally: {stderr.strip()}")
            except FileNotFoundError:
                logging.debug("Bitwarden CLI 'bw' command not found during status check")
                raise BWEnvError("Bitwarden CLI 'bw' not found. Please install it from bitwarden.com")
        
        try:
            logging.debug(f"Executing subprocess: {command}")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            logging.debug(f"Command completed successfully")
            logging.debug(f"Return code: {result.returncode}")
            logging.debug(f"Stdout length: {len(result.stdout)} chars")
            stderr_len = len(result.stderr) if hasattr(result.stderr, '__len__') else 'unknown'
            logging.debug(f"Stderr length: {stderr_len} chars")
            if result.stderr:
                logging.debug(f"Stderr content: {result.stderr}")
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ""
            logging.debug(f"Command failed with return code: {e.returncode}")
            logging.debug(f"Command failed with error: {stderr.strip()}")
            logging.debug(f"Failed command: {' '.join(command)}")
            # Check if this is an authentication error that we can handle
            if needs_auth and not os.environ.get('BW_SESSION') and ("not logged in" in stderr.lower() or "master password" in stderr.lower()):
                print("Bitwarden authentication required. Please enter your master password:", file=sys.stderr)
                try:
                    # Try to unlock the vault
                    unlock_result = subprocess.run(
                        ['bw', 'unlock', '--raw'],
                        stdin=sys.stdin,
                        stdout=subprocess.PIPE,
                        stderr=sys.stderr,
                        text=True,
                        check=True
                    )
                    session_token = unlock_result.stdout.strip()
                    os.environ['BW_SESSION'] = session_token
                    logging.debug("Successfully unlocked vault and set BW_SESSION, retrying command")
                    # Retry the original command
                    result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    logging.debug(f"Retry completed successfully, output length: {len(result.stdout)} chars")
                    return result.stdout.strip()
                except subprocess.CalledProcessError as unlock_error:
                    unlock_stderr = unlock_error.stderr or ""
                    logging.debug(f"Unlock failed: {unlock_stderr.strip()}")
                    raise BWEnvError(f"Authentication failed: {unlock_stderr.strip()}")
            raise BWEnvError(f"Bitwarden CLI error: {stderr.strip()}")
        except FileNotFoundError:
            logging.debug("Bitwarden CLI 'bw' command not found")
            raise BWEnvError("Bitwarden CLI 'bw' not found. Please install it from bitwarden.com")
    
    def sync_vault(self):
        """Sync the Bitwarden vault"""
        logging.debug("Syncing Bitwarden vault...")
        sync_start_time = __import__('time').time()
        self._run_bw_command(['sync'])
        sync_duration = __import__('time').time() - sync_start_time
        logging.debug(f"Vault sync completed in {sync_duration:.2f} seconds")
    
    def get_items_with_op_uris(self) -> List[Dict]:
        """Get all Bitwarden items that have URIs starting with 'op://'"""
        if self._items_cache is not None:
            logging.debug(f"Using cached items ({len(self._items_cache)} items)")
            return self._items_cache
        
        logging.debug("Fetching Bitwarden items with op:// URIs...")
        
        if self.sync:
            self.sync_vault()
        
        # Get all items in JSON format
        items_json = self._run_bw_command(['list', 'items', '--search', 'op://'])
        items = json.loads(items_json)
        logging.debug(f"Found {len(items)} items from search")
        logging.debug(f"Items JSON length: {len(items_json)} characters")
        
        # Filter items that have URIs starting with 'op://'
        op_items = []
        for item in items:
            if 'login' in item and item['login'] and 'uris' in item['login']:
                for uri_obj in item['login']['uris']:
                    if uri_obj.get('uri', '').startswith('op://'):
                        op_items.append(item)
                        logging.debug(f"Found item with op:// URI: {item.get('name', 'unnamed')} - URI: {uri_obj.get('uri', '')}")
                        break
        
        logging.debug(f"Filtered to {len(op_items)} items with op:// URIs")
        self._items_cache = op_items
        return op_items
    
    def find_item_by_uri_prefix(self, vault: str, item_name: str) -> Optional[Dict]:
        """Find a Bitwarden item by matching op://vault/item prefix"""
        target_prefix = f"op://{vault}/{item_name}"
        logging.debug(f"Searching for item with prefix: {target_prefix}")
        
        items = self.get_items_with_op_uris()
        for item in items:
            if 'login' in item and item['login'] and 'uris' in item['login']:
                for uri_obj in item['login']['uris']:
                    uri = uri_obj.get('uri', '')
                    if uri.startswith(target_prefix):
                        logging.debug(f"Found matching item: {item.get('name', 'unnamed')} (ID: {item.get('id', 'unknown')})")
                        logging.debug(f"Matching URI: {uri}")
                        return item
        
        logging.debug(f"No item found matching prefix: {target_prefix}")
        return None
    
    def get_field_value(self, item: Dict, field_path: str) -> Optional[str]:
        """Extract a field value from a Bitwarden item using dot notation path"""
        logging.debug(f"Looking for field '{field_path}' in item: {item.get('name', 'unnamed')}")
        logging.debug(f"Item structure: {list(item.keys())}")
        
        # Check in custom fields first
        if 'fields' in item and item['fields']:
            logging.debug(f"Checking {len(item['fields'])} custom fields")
            for field in item['fields']:
                field_name = field.get('name')
                logging.debug(f"  - Field: {field_name} (type: {field.get('type', 'unknown')})")
                if field_name == field_path:
                    logging.debug(f"Found matching field: {field_name}")
                    return field.get('value')
        
        # Check in login fields
        if 'login' in item and item['login']:
            login = item['login']
            logging.debug("Checking login fields")
            logging.debug(f"Available login fields: {list(login.keys())}")
            if field_path == 'username' and 'username' in login:
                logging.debug("Found username in login fields")
                return login['username']
            elif field_path == 'password' and 'password' in login:
                logging.debug("Found password in login fields")
                return login['password']
        
        logging.debug(f"Field '{field_path}' not found in item")
        return None


class EnvironmentProcessor:
    """Process environment variables to replace op:// URIs with secrets"""
    
    def __init__(self, bw_client: BitwardenClient):
        self.bw_client = bw_client
    
    def scan_environment(self) -> Dict[str, str]:
        """Scan environment variables for op:// URIs"""
        logging.debug("Scanning environment variables for op:// URIs...")
        op_vars = {}
        total_vars = len(os.environ)
        logging.debug(f"Checking {total_vars} environment variables")
        
        for key, value in os.environ.items():
            if URIParser.is_op_uri(value):
                logging.debug(f"Found op:// URI in {key}: {value}")
                op_vars[key] = value
        
        logging.debug(f"Found {len(op_vars)} environment variables with op:// URIs")
        if op_vars:
            logging.debug(f"Op URI variables: {list(op_vars.keys())}")
        return op_vars
    
    def resolve_uri(self, uri: str) -> str:
        """Resolve a single op:// URI to its secret value"""
        logging.debug(f"Resolving URI: {uri}")
        parsed = URIParser.parse_uri(uri)
        if not parsed:
            logging.debug(f"Invalid URI format: {uri}")
            raise BWEnvError(f"Invalid URI format: {uri}")
        
        vault, item_name, field_path = parsed
        logging.debug(f"Parsed URI - Vault: {vault}, Item: {item_name}, Field: {field_path}")
        
        # Find the Bitwarden item
        item = self.bw_client.find_item_by_uri_prefix(vault, item_name)
        if not item:
            logging.debug(f"No item found for op://{vault}/{item_name}")
            raise BWEnvError(f"No Bitwarden item found for URI: op://{vault}/{item_name}")
        
        # Get the field value
        value = self.bw_client.get_field_value(item, field_path)
        if value is None:
            logging.debug(f"Field '{field_path}' not found in item op://{vault}/{item_name}")
            raise BWEnvError(f"Field '{field_path}' not found in item: op://{vault}/{item_name}")
        
        logging.debug(f"Successfully resolved URI {uri} to value (length: {len(value)} chars)")
        logging.debug(f"Value preview: {value[:50]}{'...' if len(value) > 50 else ''}")
        return value
    
    def create_resolved_environment(self) -> Dict[str, str]:
        """Create a new environment with all op:// URIs resolved"""
        logging.debug("Creating resolved environment...")
        logging.debug(f"Starting with {len(os.environ)} environment variables")
        new_env = os.environ.copy()
        op_vars = self.scan_environment()
        
        if not op_vars:
            logging.debug("No op:// URIs found in environment variables")
            return new_env
        
        logging.debug(f"Resolving {len(op_vars)} op:// URIs...")
        for env_key, uri in op_vars.items():
            try:
                logging.debug(f"Processing {env_key}...")
                resolved_value = self.resolve_uri(uri)
                new_env[env_key] = resolved_value
                logging.debug(f"Successfully resolved {env_key}")
            except BWEnvError as e:
                logging.debug(f"Failed to resolve {env_key}: {e}")
                print(f"Error resolving {env_key}: {e}", file=sys.stderr)
                sys.exit(1)
        
        logging.debug("Environment resolution completed")
        logging.debug(f"Final environment has {len(new_env)} variables")
        return new_env


def run_command(args: argparse.Namespace):
    """Run a command with resolved environment variables"""
    logging.debug(f"Running command: {' '.join(args.cmd_args)}")
    logging.debug(f"Sync enabled: {not args.no_sync}")
    logging.debug(f"Command arguments count: {len(args.cmd_args)}")
    
    bw_client = BitwardenClient(no_sync=args.no_sync)
    processor = EnvironmentProcessor(bw_client)
    
    resolved_env = processor.create_resolved_environment()
    
    try:
        logging.debug(f"Executing command with {len(resolved_env)} environment variables")
        op_vars = processor.scan_environment()
        logging.debug(f"Resolved variables with op:// URIs: {[k for k in resolved_env.keys() if k in op_vars]}")
        # Execute the command with the resolved environment
        result = subprocess.run(
            args.cmd_args,
            env=resolved_env,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        logging.debug(f"Command completed with exit code: {result.returncode}")
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        logging.debug("Command interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.debug(f"Exception during command execution: {e}")
        print(f"Error executing command: {e}", file=sys.stderr)
        sys.exit(1)


def read_secret(args: argparse.Namespace):
    """Read a specific secret value from a URI"""
    logging.debug(f"Reading secret from URI: {args.uri}")
    logging.debug(f"Sync enabled: {not args.no_sync}")
    logging.debug(f"URI validation: {URIParser.is_op_uri(args.uri)}")
    
    bw_client = BitwardenClient(no_sync=args.no_sync)
    processor = EnvironmentProcessor(bw_client)
    
    try:
        value = processor.resolve_uri(args.uri)
        logging.debug(f"Successfully retrieved secret (length: {len(value)} chars)")
        logging.debug(f"Secret preview: {value[:20]}{'...' if len(value) > 20 else ''}")
        print(value)
    except BWEnvError as e:
        logging.debug(f"Failed to read secret: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def parse_args_with_separator():
    """Parse arguments handling the '--' separator for command isolation"""
    argv = sys.argv[1:]  # Skip script name
    
    # Find '--' separator if it exists after 'run' command
    separator_idx = None
    run_idx = None
    
    # Find 'run' command position
    for i, arg in enumerate(argv):
        if arg == 'run':
            run_idx = i
            break
    
    # If we found 'run', look for '--' after it
    if run_idx is not None:
        for i in range(run_idx + 1, len(argv)):
            if argv[i] == '--':
                separator_idx = i
                break
    
    if separator_idx is not None:
        # Split arguments at '--'
        bwenv_args = argv[:separator_idx]
        cmd_args = argv[separator_idx + 1:]
    else:
        # No '--' found, use original behavior
        bwenv_args = argv
        cmd_args = None
    
    # Parse bwenv-specific arguments
    parser = argparse.ArgumentParser(
        description="Bitwarden Environment Variable Processor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Global options
    parser.add_argument('--no-sync', action='store_true', help='Skip syncing Bitwarden vault before processing')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Run command
    run_parser = subparsers.add_parser('run', help='Run a command with resolved environment variables')
    run_parser.add_argument('--no-sync', action='store_true', help='Skip syncing Bitwarden vault before processing')
    run_parser.add_argument('--debug', action='store_true', help='Enable debug output')
    if cmd_args is None:
        # Original behavior - use REMAINDER
        run_parser.add_argument('cmd_args', nargs=argparse.REMAINDER, help='Command to execute')
    
    # Read command
    read_parser = subparsers.add_parser('read', help='Read a specific secret value')
    read_parser.add_argument('--no-sync', action='store_true', help='Skip syncing Bitwarden vault before processing')
    read_parser.add_argument('--debug', action='store_true', help='Enable debug output')
    read_parser.add_argument('uri', help='URI to read (e.g., op://Employee/example/secret)')
    
    args = parser.parse_args(bwenv_args)
    
    # If we used '--' separator, manually set cmd_args
    if cmd_args is not None and args.command == 'run':
        args.cmd_args = cmd_args
    
    return args


def main():
    args = parse_args_with_separator()
    
    if not args.command:
        # Show help and exit
        parser = argparse.ArgumentParser(
            description="Bitwarden Environment Variable Processor",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=__doc__
        )
        parser.add_argument('--no-sync', action='store_true', help='Skip syncing Bitwarden vault before processing')
        parser.add_argument('--debug', action='store_true', help='Enable debug output')
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        run_parser = subparsers.add_parser('run', help='Run a command with resolved environment variables')
        read_parser = subparsers.add_parser('read', help='Read a specific secret value')
        parser.print_help()
        sys.exit(1)
    
    # Set debug mode if requested (argparse will handle flag from either position)
    setup_logging(debug=args.debug if hasattr(args, 'debug') else False)
    if hasattr(args, 'debug') and args.debug:
        logging.debug("Debug mode enabled")
        logging.debug(f"Command: {args.command}")
        logging.debug(f"Arguments: {vars(args)}")
        logging.debug(f"Python version: {sys.version}")
        logging.debug(f"Working directory: {os.getcwd()}")
        logging.debug(f"Environment variables containing 'BW': {[k for k in os.environ.keys() if 'BW' in k.upper()]}")
    
    if args.command == 'run':
        if not hasattr(args, 'cmd_args') or not args.cmd_args:
            print("Error: No command specified to run", file=sys.stderr)
            sys.exit(1)
        run_command(args)
    elif args.command == 'read':
        read_secret(args)
    else:
        # Show help and exit
        parser = argparse.ArgumentParser(
            description="Bitwarden Environment Variable Processor",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=__doc__
        )
        parser.add_argument('--no-sync', action='store_true', help='Skip syncing Bitwarden vault before processing')
        parser.add_argument('--debug', action='store_true', help='Enable debug output')
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        run_parser = subparsers.add_parser('run', help='Run a command with resolved environment variables')
        read_parser = subparsers.add_parser('read', help='Read a specific secret value')
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()