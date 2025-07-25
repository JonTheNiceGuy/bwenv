#!/usr/bin/env python3
"""
bwenv - Bitwarden Environment Variable Processor

A cross-platform tool to replace environment variables containing Bitwarden secret references
with actual secret values using the Bitwarden CLI.

Usage:
    bwenv run [--sync] <command> [args...]
    bwenv read [--sync] <uri>

Examples:
    bwenv run sh
    bwenv read op://Employee/example/secret
    bwenv run --sync python app.py
"""

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


# Global debug flag
_DEBUG = False


def debug_print(*args, **kwargs):
    """Print debug messages when debug mode is enabled"""
    if _DEBUG:
        print("[DEBUG]", *args, file=sys.stderr, **kwargs)


def set_debug_mode(enabled: bool):
    """Enable or disable debug mode"""
    global _DEBUG
    _DEBUG = enabled


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
    
    def __init__(self, sync: bool = False):
        self.sync = sync
        self._items_cache = None
    
    def _run_bw_command(self, args: List[str]) -> str:
        """Run a Bitwarden CLI command and return stdout"""
        command = ['bw'] + args
        debug_print(f"Running Bitwarden CLI command: {' '.join(command)}")
        
        # Check if we need authentication for this command
        needs_auth = any(cmd in args for cmd in ['sync', 'list', 'get'])
        
        if needs_auth and not os.environ.get('BW_SESSION'):
            debug_print("No BW_SESSION found, checking if user is logged in...")
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
                if not status_output:
                    debug_print("Empty status response, will let command fail naturally if not authenticated")
                else:
                    try:
                        status_data = json.loads(status_output)
                        if status_data.get('status') == 'locked':
                            # Vault is locked, need to unlock interactively
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
                            debug_print("Successfully unlocked vault and set BW_SESSION")
                        elif status_data.get('status') == 'unauthenticated':
                            raise BWEnvError("You are not logged in")
                    except (json.JSONDecodeError, TypeError):
                        debug_print("Failed to parse JSON status response, will let command fail naturally if not authenticated")
            except subprocess.CalledProcessError as e:
                stderr = e.stderr or ""
                if "not logged in" in stderr or "You are not logged in" in stderr:
                    raise BWEnvError("You are not logged in")
                debug_print(f"Status check failed, will let command fail naturally: {stderr.strip()}")
            except FileNotFoundError:
                debug_print("Bitwarden CLI 'bw' command not found during status check")
                raise BWEnvError("Bitwarden CLI 'bw' not found. Please install it from bitwarden.com")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            debug_print(f"Command completed successfully, output length: {len(result.stdout)} chars")
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ""
            debug_print(f"Command failed with error: {stderr.strip()}")
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
                    debug_print("Successfully unlocked vault and set BW_SESSION, retrying command")
                    # Retry the original command
                    result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    debug_print(f"Retry completed successfully, output length: {len(result.stdout)} chars")
                    return result.stdout.strip()
                except subprocess.CalledProcessError as unlock_error:
                    unlock_stderr = unlock_error.stderr or ""
                    debug_print(f"Unlock failed: {unlock_stderr.strip()}")
                    raise BWEnvError(f"Authentication failed: {unlock_stderr.strip()}")
            raise BWEnvError(f"Bitwarden CLI error: {stderr.strip()}")
        except FileNotFoundError:
            debug_print("Bitwarden CLI 'bw' command not found")
            raise BWEnvError("Bitwarden CLI 'bw' not found. Please install it from bitwarden.com")
    
    def sync_vault(self):
        """Sync the Bitwarden vault"""
        debug_print("Syncing Bitwarden vault...")
        self._run_bw_command(['sync'])
        debug_print("Vault sync completed")
    
    def get_items_with_op_uris(self) -> List[Dict]:
        """Get all Bitwarden items that have URIs starting with 'op://'"""
        if self._items_cache is not None:
            debug_print(f"Using cached items ({len(self._items_cache)} items)")
            return self._items_cache
        
        debug_print("Fetching Bitwarden items with op:// URIs...")
        
        if self.sync:
            self.sync_vault()
        
        # Get all items in JSON format
        items_json = self._run_bw_command(['list', 'items', '--search', 'op://'])
        items = json.loads(items_json)
        debug_print(f"Found {len(items)} items from search")
        
        # Filter items that have URIs starting with 'op://'
        op_items = []
        for item in items:
            if 'login' in item and item['login'] and 'uris' in item['login']:
                for uri_obj in item['login']['uris']:
                    if uri_obj.get('uri', '').startswith('op://'):
                        op_items.append(item)
                        debug_print(f"Found item with op:// URI: {item.get('name', 'unnamed')}")
                        break
        
        debug_print(f"Filtered to {len(op_items)} items with op:// URIs")
        self._items_cache = op_items
        return op_items
    
    def find_item_by_uri_prefix(self, vault: str, item_name: str) -> Optional[Dict]:
        """Find a Bitwarden item by matching op://vault/item prefix"""
        target_prefix = f"op://{vault}/{item_name}"
        debug_print(f"Searching for item with prefix: {target_prefix}")
        
        items = self.get_items_with_op_uris()
        for item in items:
            if 'login' in item and item['login'] and 'uris' in item['login']:
                for uri_obj in item['login']['uris']:
                    uri = uri_obj.get('uri', '')
                    if uri.startswith(target_prefix):
                        debug_print(f"Found matching item: {item.get('name', 'unnamed')} (ID: {item.get('id', 'unknown')})")
                        return item
        
        debug_print(f"No item found matching prefix: {target_prefix}")
        return None
    
    def get_field_value(self, item: Dict, field_path: str) -> Optional[str]:
        """Extract a field value from a Bitwarden item using dot notation path"""
        debug_print(f"Looking for field '{field_path}' in item: {item.get('name', 'unnamed')}")
        
        # Check in custom fields first
        if 'fields' in item and item['fields']:
            debug_print(f"Checking {len(item['fields'])} custom fields")
            for field in item['fields']:
                field_name = field.get('name')
                debug_print(f"  - Field: {field_name}")
                if field_name == field_path:
                    debug_print(f"Found matching field: {field_name}")
                    return field.get('value')
        
        # Check in login fields
        if 'login' in item and item['login']:
            login = item['login']
            debug_print("Checking login fields")
            if field_path == 'username' and 'username' in login:
                debug_print("Found username in login fields")
                return login['username']
            elif field_path == 'password' and 'password' in login:
                debug_print("Found password in login fields")
                return login['password']
        
        debug_print(f"Field '{field_path}' not found in item")
        return None


class EnvironmentProcessor:
    """Process environment variables to replace op:// URIs with secrets"""
    
    def __init__(self, bw_client: BitwardenClient):
        self.bw_client = bw_client
    
    def scan_environment(self) -> Dict[str, str]:
        """Scan environment variables for op:// URIs"""
        debug_print("Scanning environment variables for op:// URIs...")
        op_vars = {}
        total_vars = len(os.environ)
        debug_print(f"Checking {total_vars} environment variables")
        
        for key, value in os.environ.items():
            if URIParser.is_op_uri(value):
                debug_print(f"Found op:// URI in {key}: {value}")
                op_vars[key] = value
        
        debug_print(f"Found {len(op_vars)} environment variables with op:// URIs")
        return op_vars
    
    def resolve_uri(self, uri: str) -> str:
        """Resolve a single op:// URI to its secret value"""
        debug_print(f"Resolving URI: {uri}")
        parsed = URIParser.parse_uri(uri)
        if not parsed:
            debug_print(f"Invalid URI format: {uri}")
            raise BWEnvError(f"Invalid URI format: {uri}")
        
        vault, item_name, field_path = parsed
        debug_print(f"Parsed URI - Vault: {vault}, Item: {item_name}, Field: {field_path}")
        
        # Find the Bitwarden item
        item = self.bw_client.find_item_by_uri_prefix(vault, item_name)
        if not item:
            debug_print(f"No item found for op://{vault}/{item_name}")
            raise BWEnvError(f"No Bitwarden item found for URI: op://{vault}/{item_name}")
        
        # Get the field value
        value = self.bw_client.get_field_value(item, field_path)
        if value is None:
            debug_print(f"Field '{field_path}' not found in item op://{vault}/{item_name}")
            raise BWEnvError(f"Field '{field_path}' not found in item: op://{vault}/{item_name}")
        
        debug_print(f"Successfully resolved URI {uri} to value (length: {len(value)} chars)")
        return value
    
    def create_resolved_environment(self) -> Dict[str, str]:
        """Create a new environment with all op:// URIs resolved"""
        debug_print("Creating resolved environment...")
        new_env = os.environ.copy()
        op_vars = self.scan_environment()
        
        if not op_vars:
            debug_print("No op:// URIs found in environment variables")
            return new_env
        
        debug_print(f"Resolving {len(op_vars)} op:// URIs...")
        for env_key, uri in op_vars.items():
            try:
                debug_print(f"Processing {env_key}...")
                resolved_value = self.resolve_uri(uri)
                new_env[env_key] = resolved_value
                debug_print(f"Successfully resolved {env_key}")
            except BWEnvError as e:
                debug_print(f"Failed to resolve {env_key}: {e}")
                print(f"Error resolving {env_key}: {e}", file=sys.stderr)
                sys.exit(1)
        
        debug_print("Environment resolution completed")
        return new_env


def run_command(args: argparse.Namespace):
    """Run a command with resolved environment variables"""
    debug_print(f"Running command: {' '.join(args.cmd_args)}")
    debug_print(f"Sync enabled: {args.sync}")
    
    bw_client = BitwardenClient(sync=args.sync)
    processor = EnvironmentProcessor(bw_client)
    
    resolved_env = processor.create_resolved_environment()
    
    try:
        debug_print(f"Executing command with {len(resolved_env)} environment variables")
        # Execute the command with the resolved environment
        result = subprocess.run(
            args.cmd_args,
            env=resolved_env,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        debug_print(f"Command completed with exit code: {result.returncode}")
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        debug_print("Command interrupted by user")
        sys.exit(130)
    except Exception as e:
        debug_print(f"Exception during command execution: {e}")
        print(f"Error executing command: {e}", file=sys.stderr)
        sys.exit(1)


def read_secret(args: argparse.Namespace):
    """Read a specific secret value from a URI"""
    debug_print(f"Reading secret from URI: {args.uri}")
    debug_print(f"Sync enabled: {args.sync}")
    
    bw_client = BitwardenClient(sync=args.sync)
    processor = EnvironmentProcessor(bw_client)
    
    try:
        value = processor.resolve_uri(args.uri)
        debug_print(f"Successfully retrieved secret (length: {len(value)} chars)")
        print(value)
    except BWEnvError as e:
        debug_print(f"Failed to read secret: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Bitwarden Environment Variable Processor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Global options
    parser.add_argument('--sync', action='store_true', help='Sync Bitwarden vault before processing')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Run command
    run_parser = subparsers.add_parser('run', help='Run a command with resolved environment variables')
    run_parser.add_argument('--sync', action='store_true', help='Sync Bitwarden vault before processing')
    run_parser.add_argument('--debug', action='store_true', help='Enable debug output')
    run_parser.add_argument('cmd_args', nargs=argparse.REMAINDER, help='Command to execute')
    
    # Read command
    read_parser = subparsers.add_parser('read', help='Read a specific secret value')
    read_parser.add_argument('--sync', action='store_true', help='Sync Bitwarden vault before processing')
    read_parser.add_argument('--debug', action='store_true', help='Enable debug output')
    read_parser.add_argument('uri', help='URI to read (e.g., op://Employee/example/secret)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Set debug mode if requested (argparse will handle flag from either position)
    if args.debug:
        set_debug_mode(True)
        debug_print("Debug mode enabled")
    
    if args.command == 'run':
        if not args.cmd_args:
            print("Error: No command specified to run", file=sys.stderr)
            sys.exit(1)
        run_command(args)
    elif args.command == 'read':
        read_secret(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()