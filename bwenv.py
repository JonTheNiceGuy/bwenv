#!/usr/bin/env python3
"""
bwenv - Bitwarden Environment Variable Processor

A cross-platform tool to replace environment variables containing Bitwarden secret references
with actual secret values using the Bitwarden CLI.

Usage:
    bwenv run [--no-sync] [--debug] <command> [args...]
    bwenv read [--no-sync] [--debug] <uri>
    bwenv send [--no-sync] [--debug] [--name <title>] [--max-access N] [--expire-hours H] <uri>...

Examples:
    bwenv run sh
    bwenv read op://Employee/example/secret
    bwenv run --no-sync python app.py
    bwenv run -- npm run build
    bwenv send --max-access 3 op://Employee/example/secret

Environment:
    BWENV_TIMEOUT   seconds to wait for each Bitwarden CLI call (default 120)
"""

import argparse
import base64
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Set, Tuple

if sys.version_info < (3, 7):
    sys.exit("bwenv needs Python 3.7 or newer")


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


IS_WINDOWS = os.name == 'nt'
SEND_DEFAULT_NAME = "Shared secret"
# Bitwarden credentials bwenv may use itself but never hands to the command it runs
BW_CREDENTIAL_VARS = ('BW_SESSION', 'BW_PASSWORD', 'BW_CLIENTID', 'BW_CLIENTSECRET')
DEFAULT_BW_TIMEOUT = 120  # seconds; override with BWENV_TIMEOUT


def bw_timeout() -> float:
    """Seconds to wait for a non-interactive bw command (BWENV_TIMEOUT, default 120)"""
    value = os.environ.get('BWENV_TIMEOUT', DEFAULT_BW_TIMEOUT)
    try:
        timeout = float(value)
    except ValueError:
        raise BWEnvError(f"BWENV_TIMEOUT must be a number of seconds, not '{value}'")
    if timeout <= 0:
        raise BWEnvError("BWENV_TIMEOUT must be greater than zero")
    return timeout


def use_utf8_stdout():
    """Write stdout as UTF-8, so a secret outside the console code page (e.g. cp1252) still prints"""
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except (ValueError, OSError):
            pass


def resolve_executable(name: str) -> str:
    """Find a command the way the shell would.

    Windows' CreateProcess only tries '.exe', so an npm-installed bw.cmd is never found without
    looking it up through PATHEXT first. Elsewhere the OS already searches PATH.
    """
    if IS_WINDOWS:
        return shutil.which(name) or name
    return name


class URIParser:
    """Parser for op:// and bw:// URIs"""
    
    OP_URI_PATTERN = re.compile(r'^op://([^/]+)/([^/]+)/(.+)$')
    OP_ITEM_URI_PATTERN = re.compile(r'^op://([^/]+)/([^/]+)$')
    BW_URI_PATTERN = re.compile(r'^bw://([^/]+)/(.+)/([^/]+)/(.+)$')
    
    @classmethod
    def parse_op_uri(cls, uri: str) -> Optional[Tuple[str, str, str]]:
        """
        Parse a URI in the format op://vaultname/item/keyname
        
        Returns:
            Tuple of (vaultname, item, keyname) or None if invalid
        """
        match = cls.OP_URI_PATTERN.match(uri)
        if not match:
            return None
        vault, item, keyname = match.groups()
        return (vault, item, keyname)
    
    @classmethod
    def parse_op_item_uri(cls, uri: str) -> Optional[Tuple[str, str]]:
        """Parse an item-only URI, op://vaultname/item (used by send). Returns (vaultname, item) or None."""
        match = cls.OP_ITEM_URI_PATTERN.match(uri)
        return (match.group(1), match.group(2)) if match else None
    
    @classmethod
    def parse_bw_uri(cls, uri: str) -> Optional[str]:
        """
        Validate a bw:// URI format - just check if it starts with bw:// and has at least 2 slashes
        
        Returns:
            The URI string if valid, None if invalid
        """
        if not uri.startswith('bw://'):
            return None
        
        # Count slashes after bw://
        path_part = uri[5:]  # Remove bw:// prefix
        slash_count = path_part.count('/')
        
        if slash_count < 2:  # Need at least org/item/field
            return None
            
        return uri
    
    @classmethod
    def parse_uri(cls, uri: str) -> Optional[Tuple[str, str, str]]:
        """Backward compatibility method - delegates to parse_op_uri"""
        return cls.parse_op_uri(uri)
    
    @classmethod
    def is_op_uri(cls, value: str) -> bool:
        """Check if a string is a valid op:// URI"""
        return cls.parse_op_uri(value) is not None
    
    @classmethod
    def is_bw_uri(cls, value: str) -> bool:
        """Check if a string is a valid bw:// URI"""
        return cls.parse_bw_uri(value) is not None
    
    @classmethod
    def is_supported_uri(cls, value: str) -> bool:
        """Check if a string is any supported URI format"""
        return cls.is_op_uri(value) or cls.is_bw_uri(value)


class BitwardenClient:
    """Client for interacting with Bitwarden CLI"""
    
    # Commands that need an unlocked vault
    AUTH_COMMANDS = ('sync', 'list', 'get', 'send')
    
    def __init__(self, no_sync: bool = False):
        self.sync = not no_sync
        self._session = os.environ.get('BW_SESSION')
        self._session_checked = False
        self._items_cache = None
        self._op_items_cache = None
        self._organizations_cache = None
        self._folders_cache = None
        self._collections_cache = None

    def _bw_env(self) -> Dict[str, str]:
        """Environment for bw: ours, plus the session this client unlocked (os.environ is never changed)"""
        env = os.environ.copy()
        if self._session:
            env['BW_SESSION'] = self._session
        return env

    def _exec_bw(self, args: List[str], input_text: Optional[str] = None,
                 interactive: bool = False) -> subprocess.CompletedProcess:
        """Run bw and return the completed process. Only the subcommand is logged, never the arguments."""
        command = [resolve_executable('bw')] + args
        logging.debug(f"Running Bitwarden CLI command: bw {' '.join(args[:2])}")
        try:
            if interactive:
                # The master password prompt needs the terminal: inherit stdin and stderr, capture the token.
                return subprocess.run(command, stdout=subprocess.PIPE, encoding='utf-8', env=self._bw_env())
            timeout = bw_timeout()
            return subprocess.run(command, input=input_text, capture_output=True, encoding='utf-8',
                                  env=self._bw_env(), timeout=timeout)
        except FileNotFoundError:
            raise BWEnvError("Bitwarden CLI 'bw' not found. Please install it from bitwarden.com")
        except subprocess.TimeoutExpired:
            raise BWEnvError(f"'bw {args[0]}' did not finish within {bw_timeout():g} seconds. Is the Bitwarden "
                             f"server reachable? Set BWENV_TIMEOUT to allow longer.")

    def _run_bw_command(self, args: List[str], input_text: Optional[str] = None) -> str:
        """Run a Bitwarden CLI command and return stdout"""
        if args and args[0] in self.AUTH_COMMANDS:
            self._ensure_unlocked()
        
        result = self._exec_bw(args, input_text)
        logging.debug(f"bw {args[0]} exited {result.returncode}, stdout {len(result.stdout or '')} chars")
        if result.returncode != 0:
            stderr = result.stderr.strip() if isinstance(result.stderr, str) else ''
            raise BWEnvError(f"Bitwarden CLI error running 'bw {args[0]}': {stderr or f'exit code {result.returncode}'}")
        return result.stdout.strip()
    
    def _ensure_unlocked(self):
        """Check the vault state once per client, unlocking it if it is locked"""
        if self._session_checked:
            return
        
        result = self._exec_bw(['status'])
        try:
            status = json.loads(result.stdout).get('status')
        except (json.JSONDecodeError, TypeError, AttributeError):
            status = None
        logging.debug(f"Vault status: {status}")
        
        if status == 'unauthenticated':
            raise BWEnvError("You are not logged in to Bitwarden. Run `bw login` first.")
        if status == 'locked':
            self._unlock()
        # 'unlocked', or a status we cannot read: let the command itself report any problem
        self._session_checked = True
    
    def _unlock(self):
        """Ask for the master password on the terminal and keep the session for this client"""
        if not sys.stdin.isatty():
            raise BWEnvError("The Bitwarden vault is locked and there is no terminal to ask for the master "
                             "password. Unlock it first, e.g. export BW_SESSION=\"$(bw unlock --raw)\"")
        
        print("Bitwarden vault is locked. Please enter your master password to unlock:", file=sys.stderr)
        result = self._exec_bw(['unlock', '--raw'], interactive=True)
        session = (result.stdout or '').strip()
        if result.returncode != 0 or not session:
            raise BWEnvError(f"Failed to unlock the Bitwarden vault (bw unlock exited {result.returncode})")
        self._session = session
        logging.debug("Vault unlocked")
    
    def sync_vault(self):
        """Sync the Bitwarden vault"""
        logging.debug("Syncing Bitwarden vault...")
        sync_start_time = __import__('time').time()
        self._run_bw_command(['sync'])
        sync_duration = __import__('time').time() - sync_start_time
        logging.debug(f"Vault sync completed in {sync_duration:.2f} seconds")
    
    def _get_all_items(self) -> List[Dict]:
        """Get every item in the vault, syncing first, cached for the life of the client"""
        if self._items_cache is not None:
            logging.debug(f"Using cached items ({len(self._items_cache)} items)")
            return self._items_cache

        if self.sync:
            self.sync_vault()

        items_json = self._run_bw_command(['list', 'items'])
        self._items_cache = json.loads(items_json)
        logging.debug(f"Found {len(self._items_cache)} total items")
        logging.debug(f"Items JSON length: {len(items_json)} characters")
        return self._items_cache

    def get_items_with_op_uris(self) -> List[Dict]:
        """Get all Bitwarden items that have URIs starting with 'op://'"""
        if self._op_items_cache is not None:
            logging.debug(f"Using cached op:// items ({len(self._op_items_cache)} items)")
            return self._op_items_cache

        logging.debug("Fetching Bitwarden items with op:// URIs...")

        # Filter locally: `bw list items --search` no longer matches website URIs (bw 2026.9.1),
        # so searching for 'op://' would find nothing.
        items = self._get_all_items()

        # Filter items that have URIs starting with 'op://'
        op_items = []
        for item in items:
            if item.get('login') and item['login'].get('uris'):
                for uri_obj in item['login']['uris']:
                    if uri_obj.get('uri', '').startswith('op://'):
                        op_items.append(item)
                        logging.debug(f"Found item with op:// URI: {item.get('name', 'unnamed')} - URI: {uri_obj.get('uri', '')}")
                        break
        
        logging.debug(f"Filtered to {len(op_items)} items with op:// URIs")
        self._op_items_cache = op_items
        return op_items
    
    def find_item_by_uri_prefix(self, vault: str, item_name: str) -> Optional[Dict]:
        """Find the one Bitwarden item whose website URI is op://vault/item.
        
        The URI must match exactly (a trailing slash is allowed): op://Prod/db is not op://Prod/db-prod.
        Two different items carrying the same reference is an error rather than a guess, since an item
        shared into any collection you can read could otherwise shadow yours.
        """
        target = f"op://{vault}/{item_name}"
        logging.debug(f"Searching for item with URI: {target}")
        
        matches = []
        for item in self.get_items_with_op_uris():
            uris = (item.get('login') or {}).get('uris') or []
            if any((uri_obj.get('uri') or '').rstrip('/') == target for uri_obj in uris):
                if all(item.get('id') != match.get('id') for match in matches):
                    matches.append(item)
        
        if len(matches) > 1:
            raise BWEnvError(f"{len(matches)} Bitwarden items have the URI {target}; keep it on exactly one item")
        if matches:
            logging.debug(f"Found matching item: {matches[0].get('name', 'unnamed')} (ID: {matches[0].get('id', 'unknown')})")
            return matches[0]
        
        logging.debug(f"No item found with URI: {target}")
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
    
    def _resolve_organization(self, org_or_vault: str) -> Optional[str]:
        """Resolve organization name to UUID, return None for personal vault"""
        if org_or_vault in ['myvault', 'unassigned']:
            logging.debug(f"'{org_or_vault}' refers to personal vault")
            return None
        
        # Check if it's already a UUID (contains hyphens in UUID pattern)
        if len(org_or_vault) == 36 and org_or_vault.count('-') == 4:
            logging.debug(f"'{org_or_vault}' appears to be a UUID")
            return org_or_vault
        
        # List organizations to resolve name to UUID; a failure to list them is a real error
        if self._organizations_cache is not None:
            logging.debug(f"Using cached organizations ({len(self._organizations_cache)} organizations)")
            organizations = self._organizations_cache
        else:
            orgs_json = self._run_bw_command(['list', 'organizations'])
            organizations = json.loads(orgs_json)
            logging.debug(f"Found {len(organizations)} organizations")
            self._organizations_cache = organizations
        
        for org in organizations:
            if org.get('name') == org_or_vault:
                org_id = org.get('id')
                logging.debug(f"Resolved organization '{org_or_vault}' to ID: {org_id}")
                return org_id
        
        raise BWEnvError(f"Organization '{org_or_vault}' not found (use its name or UUID, or 'myvault' for your own vault)")
    
    def _get_folders(self) -> List[Dict]:
        """Get all personal vault folders, cached for the life of the client"""
        if self._folders_cache is not None:
            logging.debug(f"Using cached folders ({len(self._folders_cache)} folders)")
            return self._folders_cache
        folders_json = self._run_bw_command(['list', 'folders'])
        self._folders_cache = json.loads(folders_json)
        logging.debug(f"Found {len(self._folders_cache)} folders")
        return self._folders_cache
    
    def _get_collections(self) -> List[Dict]:
        """Get all organization collections, cached for the life of the client"""
        if self._collections_cache is not None:
            logging.debug(f"Using cached collections ({len(self._collections_cache)} collections)")
            return self._collections_cache
        collections_json = self._run_bw_command(['list', 'collections'])
        self._collections_cache = json.loads(collections_json)
        logging.debug(f"Found {len(self._collections_cache)} collections")
        return self._collections_cache
    
    def _resolve_path_ids(self, org_id: Optional[str], path: str) -> Set[str]:
        """Resolve a path to the IDs of the folders (personal vault) or collections (organization) it names.
        
        Only an exact match counts: the full name (e.g. 'Demo/Data' for a nested collection) or the UUID.
        """
        if org_id is None:
            containers = self._get_folders()
        else:
            containers = [c for c in self._get_collections() if c.get('organizationId') == org_id]
        
        resolved = {c['id'] for c in containers if c.get('id') and path in (c.get('name'), c.get('id'))}
        logging.debug(f"Resolved path '{path}' to IDs: {resolved}")
        return resolved
    
    def _item_in_containers(self, item: Dict, org_id: Optional[str], container_ids: Set[str]) -> bool:
        """Check if an item is in one of the given folders (personal vault) or collections (organization)"""
        if org_id is None:
            return item.get('folderId') in container_ids
        return bool(set(item.get('collectionIds') or []) & container_ids)
    
    def find_bw_item(self, uri: str) -> Tuple[Dict, str]:
        """Find the item a bw:// URI names. Returns (item, field_name); field_name is '' for a whole-item URI."""
        logging.debug(f"Starting bw:// URI resolution: {uri}")
        
        if not uri.startswith('bw://'):
            raise BWEnvError(f"Invalid bw:// URI: {uri}")
        
        parts = uri[5:].split('/')
        if len(parts) < 2:
            raise BWEnvError(f"bw:// URI must have at least org/item: {uri}")
        
        org_or_vault = parts[0]
        remaining_parts = parts[1:]  # Everything after org
        logging.debug(f"Org/vault: {org_or_vault}, remaining parts: {remaining_parts}")
        
        org_id = self._resolve_organization(org_or_vault)
        logging.debug(f"Resolved organization '{org_or_vault}' to ID: {org_id}")
        
        # Try different splits of the remaining parts into path / item / field
        item, field_name = self._find_item_with_field_from_parts(org_id, remaining_parts)
        if not item:
            raise BWEnvError(f"No item found for bw:// URI: {uri}")
        return item, field_name
    
    def resolve_bw_uri_to_value(self, uri: str) -> str:
        """Resolve a complete bw:// URI to its field value"""
        item, field_name = self.find_bw_item(uri)
        if not field_name:
            raise BWEnvError(f"bw:// URI names an item, not a field: {uri}")
        
        value = self.get_field_value(item, field_name)
        if value is None:
            raise BWEnvError(f"Field '{field_name}' not found in item '{item.get('name')}'")
        return value
    
    def _find_item_with_field_from_parts(self, org_id: Optional[str], parts: List[str]) -> Tuple[Optional[Dict], str]:
        """Try different combinations of parts to find an item with the field"""
        logging.debug(f"Searching for item with org_id={org_id} and parts={parts}")
        
        items = self._get_all_items()

        # Filter items by organization first
        candidate_items = []
        for item in items:
            item_org_id = item.get('organizationId')
            if org_id == item_org_id:  # This handles both None==None and uuid==uuid
                candidate_items.append(item)
        
        logging.debug(f"Found {len(candidate_items)} items matching organization constraint")
        
        # Try different splits of parts into path / item_name / field_name.
        # Everything before the item name is the folder (personal vault) or collection (organization).
        for split_point in range(1, len(parts) + 1):  # Try different split points, including full length
            potential_path = '/'.join(parts[:split_point - 1])
            potential_item_name = parts[split_point - 1]
            potential_field_name = '/'.join(parts[split_point:]) if split_point < len(parts) else ""

            logging.debug(f"Trying path='{potential_path}', item_name='{potential_item_name}', field_name='{potential_field_name}'")

            matches = [item for item in candidate_items if item.get('name') == potential_item_name]
            if not matches:
                continue
            logging.debug(f"Found {len(matches)} item(s) named '{potential_item_name}'")

            if potential_path:
                container_ids = self._resolve_path_ids(org_id, potential_path)
                matches = [item for item in matches if self._item_in_containers(item, org_id, container_ids)]
                logging.debug(f"{len(matches)} item(s) in '{potential_path}'")

            if potential_field_name:
                matches = [item for item in matches if self.get_field_value(item, potential_field_name) is not None]
                logging.debug(f"{len(matches)} item(s) have field '{potential_field_name}'")

            if len(matches) > 1:
                where = f"'{potential_path}'" if potential_path else "this vault"
                raise BWEnvError(f"{len(matches)} items named '{potential_item_name}' match in {where}; "
                                 f"add the folder or collection to the URI to choose one")
            if matches:
                logging.debug("Match found!")
                return matches[0], potential_field_name

        logging.debug("No matching item found")
        return None, ""
    
    def send_item(self, uri: str, name: Optional[str] = None, max_access: Optional[int] = 1,
                  expire_hours: float = 24.0) -> str:
        """Create a Bitwarden Send of a field value, or of a whole item as JSON, and return its URL.
        
        Defaults are deliberately tight: one view, text hidden until revealed, sender email hidden,
        deleted after 24 hours, and a generic name that does not reveal the URI.
        """
        text = self._send_text(uri)
        deletion = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=expire_hours)
        send_data = {
            "object": "send",
            "type": 0,  # Text send
            "name": name or SEND_DEFAULT_NAME,
            "text": {
                "text": text,
                "hidden": True
            },
            "file": None,
            "maxAccessCount": max_access or None,  # 0 or None: unlimited
            "deletionDate": deletion.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            "expirationDate": None,
            "password": None,
            "disabled": False,
            "hideEmail": True
        }
        return self._create_send(send_data)
    
    def _send_text(self, uri: str) -> str:
        """The text to Send for a URI: the field's value, or the whole item as JSON"""
        if URIParser.is_op_uri(uri):
            return EnvironmentProcessor(self)._resolve_op_uri(uri)
        
        op_item = URIParser.parse_op_item_uri(uri)
        if op_item:
            item = self.find_item_by_uri_prefix(*op_item)
            if not item:
                raise BWEnvError(f"No Bitwarden item found for URI: {uri}")
            return self._item_as_json(item)
        
        if uri.startswith('bw://'):
            item, field_name = self.find_bw_item(uri)
            if not field_name:
                return self._item_as_json(item)
            value = self.get_field_value(item, field_name)
            if value is None:
                raise BWEnvError(f"Field '{field_name}' not found in item '{item.get('name')}'")
            return value
        
        raise BWEnvError(f"Invalid URI format: {uri}")
    
    @staticmethod
    def _item_as_json(item: Dict) -> str:
        """The username, password and custom fields of an item, as JSON"""
        item_data = {}
        login = item.get('login') or {}
        if login.get('username'):
            item_data['username'] = login['username']
        if login.get('password'):
            item_data['password'] = login['password']
        for field in item.get('fields') or []:
            if field.get('name') and field.get('value'):
                item_data[field['name']] = field['value']
        return json.dumps(item_data, indent=2)
    
    def _create_send(self, send_data: Dict) -> str:
        """Create a Send and return its access URL. The payload goes to bw on stdin, never in argv or logs."""
        logging.debug(f"Creating Send '{send_data['name']}' (max access: {send_data['maxAccessCount']}, "
                      f"deleted: {send_data['deletionDate']})")
        
        # Equivalent to `bw encode`, without an extra bw process
        encoded = base64.b64encode(json.dumps(send_data).encode('utf-8')).decode('ascii')
        result = self._run_bw_command(['send', 'create'], input_text=encoded)
        
        try:
            access_url = json.loads(result).get('accessUrl')
        except (json.JSONDecodeError, AttributeError):
            access_url = None
        if not access_url:
            # Do not echo bw's output: it contains the Send, secret included
            raise BWEnvError("bw send create did not return an access URL")
        return access_url


class EnvironmentProcessor:
    """Process environment variables to replace op:// and bw:// URIs with secrets"""
    
    def __init__(self, bw_client: BitwardenClient):
        self.bw_client = bw_client
    
    def scan_environment(self) -> Dict[str, str]:
        """Scan environment variables for op:// and bw:// URIs"""
        logging.debug("Scanning environment variables for op:// and bw:// URIs...")
        uri_vars = {}
        total_vars = len(os.environ)
        logging.debug(f"Checking {total_vars} environment variables")
        
        for key, value in os.environ.items():
            if URIParser.is_supported_uri(value):
                logging.debug(f"Found supported URI in {key}: {value}")
                uri_vars[key] = value
        
        logging.debug(f"Found {len(uri_vars)} environment variables with supported URIs")
        if uri_vars:
            logging.debug(f"URI variables: {list(uri_vars.keys())}")
        return uri_vars
    
    def resolve_uri(self, uri: str) -> str:
        """Resolve a single op:// or bw:// URI to its secret value"""
        logging.debug(f"Resolving URI: {uri}")
        
        if URIParser.is_op_uri(uri):
            return self._resolve_op_uri(uri)
        elif URIParser.is_bw_uri(uri):
            return self._resolve_bw_uri(uri)
        else:
            logging.debug(f"Invalid URI format: {uri}")
            raise BWEnvError(f"Invalid URI format: {uri}")
    
    def _resolve_op_uri(self, uri: str) -> str:
        """Resolve an op:// URI to its secret value"""
        parsed = URIParser.parse_op_uri(uri)
        if not parsed:
            logging.debug(f"Invalid op:// URI format: {uri}")
            raise BWEnvError(f"Invalid op:// URI format: {uri}")
        
        vault, item_name, field_path = parsed
        logging.debug(f"Parsed op:// URI - Vault: {vault}, Item: {item_name}, Field: {field_path}")
        
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
        
        logging.debug(f"Successfully resolved op:// URI {uri} to value (length: {len(value)} chars)")
        return value
    
    def _resolve_bw_uri(self, uri: str) -> str:
        """Resolve a bw:// URI to its secret value"""
        if not URIParser.is_bw_uri(uri):
            logging.debug(f"Invalid bw:// URI format: {uri}")
            raise BWEnvError(f"Invalid bw:// URI format: {uri}")
        
        logging.debug(f"Resolving bw:// URI: {uri}")
        
        # Parsing and resolution are handled by BitwardenClient.resolve_bw_uri_to_value
        try:
            value = self.bw_client.resolve_bw_uri_to_value(uri)
            logging.debug(f"Successfully resolved bw:// URI {uri} to value (length: {len(value)} chars)")
            return value
        except (BWEnvError, ValueError) as e:
            logging.debug(f"Failed to resolve bw:// URI {uri}: {e}")
            raise BWEnvError(f"Failed to resolve bw:// URI {uri}: {e}")
    
    def create_resolved_environment(self) -> Dict[str, str]:
        """Create a new environment with all supported URIs resolved"""
        logging.debug("Creating resolved environment...")
        logging.debug(f"Starting with {len(os.environ)} environment variables")
        new_env = os.environ.copy()
        # The child gets the secrets it references, not the means to read the rest of the vault
        for key in BW_CREDENTIAL_VARS:
            new_env.pop(key, None)
        uri_vars = self.scan_environment()
        
        if not uri_vars:
            logging.debug("No supported URIs found in environment variables")
            return new_env
        
        logging.debug(f"Resolving {len(uri_vars)} supported URIs...")
        for env_key, uri in uri_vars.items():
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
    """Run a command with resolved environment variables. Does not return."""
    logging.debug(f"Running command: {args.cmd_args[0]} (+{len(args.cmd_args) - 1} arguments)")
    logging.debug(f"Sync enabled: {not args.no_sync}")
    
    bw_client = BitwardenClient(no_sync=args.no_sync)
    processor = EnvironmentProcessor(bw_client)
    resolved_env = processor.create_resolved_environment()
    exec_command(args.cmd_args, resolved_env)


def exec_command(cmd_args: List[str], env: Dict[str, str]):
    """Hand over to the command, so signals and the exit status are its own. Does not return.
    
    On POSIX bwenv replaces itself with the command (exec): Ctrl-C and SIGTERM reach it directly,
    its exit status (including death by signal) is bwenv's, and no bwenv process stays behind
    holding the secrets. Windows has no real exec, so bwenv waits for the command instead.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        if not IS_WINDOWS:
            os.execvpe(cmd_args[0], cmd_args, env)
        process = subprocess.Popen([resolve_executable(cmd_args[0])] + cmd_args[1:], env=env)
    except FileNotFoundError:
        print(f"Error executing command: '{cmd_args[0]}' not found", file=sys.stderr)
        sys.exit(127)
    except OSError as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        sys.exit(126)
    
    while True:
        try:
            sys.exit(process.wait())
        except KeyboardInterrupt:
            # The console delivered Ctrl-C to the command too; let it decide when to exit
            continue


def read_secret(args: argparse.Namespace):
    """Read a specific secret value from a URI"""
    logging.debug(f"Reading secret from URI: {args.uri}")
    logging.debug(f"Sync enabled: {not args.no_sync}")
    logging.debug(f"URI validation - op://: {URIParser.is_op_uri(args.uri)}, bw://: {URIParser.is_bw_uri(args.uri)}")
    
    bw_client = BitwardenClient(no_sync=args.no_sync)
    processor = EnvironmentProcessor(bw_client)
    
    try:
        value = processor.resolve_uri(args.uri)
        logging.debug(f"Successfully retrieved secret (length: {len(value)} chars)")
        use_utf8_stdout()
        print(value)
    except BWEnvError as e:
        logging.debug(f"Failed to read secret: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def send_item(args: argparse.Namespace):
    """Create a Bitwarden Send from each URI and print its URL"""
    logging.debug(f"Creating send from {len(args.uri)} URI(s)")
    
    bw_client = BitwardenClient(no_sync=args.no_sync)
    base_name = args.name or SEND_DEFAULT_NAME
    use_utf8_stdout()
    total = len(args.uri)
    
    try:
        for index, uri in enumerate(args.uri, start=1):
            name = f"{base_name} ({index} of {total})" if total > 1 else base_name
            send_url = bw_client.send_item(uri, name, args.max_access, args.expire_hours)
            print(f"{uri} - {send_url}" if total > 1 else send_url)
    except BWEnvError as e:
        logging.debug(f"Failed to create send: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


BWENV_FLAGS = ('--debug', '--no-sync')
SUBCOMMANDS = ('run', 'read', 'send')


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser for bwenv's subcommands (--debug/--no-sync are extracted beforehand)"""
    parser = argparse.ArgumentParser(
        description="Bitwarden Environment Variable Processor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--no-sync', action='store_true', help='Skip syncing Bitwarden vault before processing')
    parser.add_argument('--debug', action='store_true', help='Enable debug output (never includes secret values)')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    subparsers.add_parser('run', help='Run a command with resolved environment variables')
    
    read_parser = subparsers.add_parser('read', help='Read a specific secret value')
    read_parser.add_argument('uri', help='URI to read (e.g., op://Employee/example/secret)')
    
    send_parser = subparsers.add_parser('send', help='Create a Bitwarden Send from a URI')
    send_parser.add_argument('uri', help='URI(s) to send (e.g., op://Employee/example/secret or bw://MyOrg/Collection/Path/item/custom/field)', nargs="+")
    send_parser.add_argument('--name', help=f'Name for the send (default: "{SEND_DEFAULT_NAME}")')
    send_parser.add_argument('--max-access', type=int, default=1,
                             help='How many times the send can be opened; 0 for unlimited (default: 1)')
    send_parser.add_argument('--expire-hours', type=float, default=24.0,
                             help='Hours until the send is deleted (default: 24)')
    return parser


def parse_args_with_separator(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse bwenv's arguments, keeping the child command of `run` intact.
    
    --debug and --no-sync may appear before or after the subcommand. For `run`, they are only
    recognised up to the start of the child command or the first `--`; everything from there on is
    the child's, unchanged - including words such as run/read/send and any further `--`.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    flags = set()
    
    # Before the subcommand: bwenv flags only
    i = 0
    while i < len(argv) and argv[i] in BWENV_FLAGS:
        flags.add(argv[i])
        i += 1
    if i < len(argv) and argv[i] == '--':
        print("Error: '--' separator must come after 'run' command", file=sys.stderr)
        sys.exit(1)
    
    command = argv[i] if i < len(argv) else None
    rest = argv[i + 1:]
    cmd_args = None
    
    if command == 'run':
        j = 0
        while j < len(rest) and rest[j] in BWENV_FLAGS:
            flags.add(rest[j])
            j += 1
        if j < len(rest) and rest[j] in ('-h', '--help'):
            bwenv_args = ['run', rest[j]]  # bwenv's own help for run
        else:
            if j < len(rest) and rest[j] == '--':
                j += 1
            cmd_args = rest[j:]
            bwenv_args = ['run']
    else:
        # read and send run no child command, so bwenv flags may appear anywhere
        flags.update(arg for arg in rest if arg in BWENV_FLAGS)
        bwenv_args = argv[i:i + 1] + [arg for arg in rest if arg not in BWENV_FLAGS]
    
    args = build_parser().parse_args(bwenv_args)
    args.debug = '--debug' in flags
    args.no_sync = '--no-sync' in flags
    if args.command == 'run':
        args.cmd_args = cmd_args or []
    return args


def main():
    args = parse_args_with_separator()
    
    if args.command not in SUBCOMMANDS:
        build_parser().print_help()
        sys.exit(1)
    
    setup_logging(debug=args.debug)
    if args.debug:
        logging.debug("Debug mode enabled")
        logging.debug(f"Command: {args.command}")
        logging.debug(f"Python version: {sys.version}")
        logging.debug(f"Working directory: {os.getcwd()}")
        logging.debug(f"Environment variables containing 'BW': {[k for k in os.environ.keys() if 'BW' in k.upper()]}")
    
    if args.command == 'run':
        if not args.cmd_args:
            print("Error: No command specified to run", file=sys.stderr)
            sys.exit(1)
        run_command(args)
    elif args.command == 'read':
        read_secret(args)
    elif args.command == 'send':
        send_item(args)


if __name__ == '__main__':
    main()