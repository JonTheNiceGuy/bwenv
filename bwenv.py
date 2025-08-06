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
    """Parser for op:// and bw:// URIs"""
    
    OP_URI_PATTERN = re.compile(r'^op://([^/]+)/([^/]+)/(.+)$')
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
        
        if needs_auth:
            # Always check status if we need auth, even if BW_SESSION is set (could be expired)
            self._validate_session()
        
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
    
    def _validate_session(self):
        """Validate the current BW_SESSION if it exists"""
        bw_session = os.environ.get('BW_SESSION')
        
        if not bw_session:
            logging.debug("No BW_SESSION to validate")
            return
        
        logging.debug("Validating BW_SESSION...")
        try:
            status_result = subprocess.run(
                ['bw', 'status'],
                capture_output=True,
                text=True,
                check=True
            )
            status_output = status_result.stdout.strip()
            logging.debug(f"Session validation - status output: {status_output}")
            
            if not status_output:
                logging.debug("Empty status response during session validation")
                return
            
            try:
                status_data = json.loads(status_output)
                # Handle case where status might return a list or other structure
                if isinstance(status_data, dict):
                    status = status_data.get('status')
                    logging.debug(f"Session validation - parsed status: {status}")
                else:
                    logging.debug(f"Session validation - unexpected status format: {type(status_data)}")
                    return
                
                if status == 'locked':
                    logging.debug("Session exists but vault is locked - requesting unlock")
                    # Session is valid but vault is locked, unlock it now
                    try:
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
                        logging.debug("Successfully unlocked vault and updated BW_SESSION during validation")
                    except subprocess.CalledProcessError as unlock_error:
                        unlock_stderr = unlock_error.stderr or ""
                        logging.debug(f"Unlock failed during session validation: {unlock_stderr.strip()}")
                        # Clear the session since unlock failed
                        if 'BW_SESSION' in os.environ:
                            del os.environ['BW_SESSION']
                        raise BWEnvError(f"Failed to unlock vault: {unlock_stderr.strip()}")
                elif status == 'unauthenticated':
                    logging.debug("BW_SESSION is invalid/expired, clearing it")
                    # Session is invalid, remove it so auth flow can handle login
                    del os.environ['BW_SESSION']
                elif status == 'unlocked':
                    logging.debug("BW_SESSION is valid and vault is unlocked")
                else:
                    logging.debug(f"Unknown status during session validation: {status}")
                    
            except (json.JSONDecodeError, TypeError) as e:
                logging.debug(f"Failed to parse status JSON during session validation: {e}")
                
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ""
            logging.debug(f"Session validation failed: {stderr.strip()}")
            if "not logged in" in stderr.lower() or "unauthenticated" in stderr.lower():
                logging.debug("Session validation indicates unauthenticated, clearing BW_SESSION")
                if 'BW_SESSION' in os.environ:
                    del os.environ['BW_SESSION']
        except FileNotFoundError:
            logging.debug("Bitwarden CLI 'bw' command not found during session validation")
    
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
    
    def find_item_by_bw_uri(self, org_or_vault: str, path: str, item_name: str) -> Optional[Dict]:
        """Find a Bitwarden item by bw:// URI components"""
        logging.debug(f"Searching for item with bw:// URI - org/vault: {org_or_vault}, path: {path}, item: {item_name}")
        
        if self.sync:
            self.sync_vault()
        
        # Step 1: Resolve organization name to UUID if needed
        org_id = self._resolve_organization(org_or_vault)
        logging.debug(f"Resolved org/vault '{org_or_vault}' to ID: {org_id}")
        
        # Step 2: Resolve path (folders/collections) to UUIDs
        path_constraints = self._resolve_path_constraints(org_id, path)
        logging.debug(f"Resolved path constraints: {path_constraints}")
        
        # Step 3: Get all items and find matching one
        items_json = self._run_bw_command(['list', 'items'])
        items = json.loads(items_json)
        logging.debug(f"Found {len(items)} total items for bw:// search")
        
        # Search for item by name and constraints
        for item in items:
            if item.get('name') == item_name:
                logging.debug(f"Found matching item name: {item_name}")
                logging.debug(f"Item details - org: {item.get('organizationId')}, collection: {item.get('collectionIds', [])}, folder: {item.get('folderId')}")
                
                if self._item_matches_constraints(item, org_id, path_constraints):
                    logging.debug(f"Item matches all constraints")
                    return item
                else:
                    logging.debug(f"Item does not match constraints")
        
        logging.debug(f"No item found matching bw:// URI components")
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
        
        try:
            # List organizations to resolve name to UUID
            orgs_json = self._run_bw_command(['list', 'organizations'])
            organizations = json.loads(orgs_json)
            logging.debug(f"Found {len(organizations)} organizations")
            
            for org in organizations:
                if org.get('name') == org_or_vault:
                    org_id = org.get('id')
                    logging.debug(f"Resolved organization '{org_or_vault}' to ID: {org_id}")
                    return org_id
            
            # If not found by name, maybe it's still a UUID we don't recognize
            logging.debug(f"Organization '{org_or_vault}' not found by name, treating as UUID")
            return org_or_vault
            
        except Exception as e:
            logging.debug(f"Failed to list organizations: {e}")
            return org_or_vault
    
    def _resolve_path_constraints(self, org_id: Optional[str], path: str) -> Dict[str, str]:
        """Resolve path components (folders/collections) to UUIDs"""
        constraints = {}
        
        if not path:
            logging.debug("Empty path, no constraints")
            return constraints
        
        # Split path into components
        path_parts = [p.strip() for p in path.split('/') if p.strip()]
        logging.debug(f"Path parts: {path_parts}")
        
        if org_id is None:
            # Personal vault - resolve folders
            constraints.update(self._resolve_folders(path_parts))
        else:
            # Organization vault - resolve collections
            constraints.update(self._resolve_collections(org_id, path_parts))
        
        return constraints
    
    def _resolve_folders(self, path_parts: List[str]) -> Dict[str, str]:
        """Resolve folder names to UUIDs for personal vault"""
        resolved = {}
        
        try:
            folders_json = self._run_bw_command(['list', 'folders'])
            folders = json.loads(folders_json)
            logging.debug(f"Found {len(folders)} folders")
            
            for folder in folders:
                folder_name = folder.get('name', '')
                folder_id = folder.get('id')
                
                if folder_name in path_parts and folder_id:
                    resolved[folder_name] = folder_id
                    logging.debug(f"Resolved folder '{folder_name}' to ID: {folder_id}")
                    
        except Exception as e:
            logging.debug(f"Failed to list folders: {e}")
        
        return resolved
    
    def _resolve_collections(self, org_id: str, path_parts: List[str]) -> Dict[str, str]:
        """Resolve collection names to UUIDs for organization vault"""
        resolved = {}
        
        if not path_parts:
            return resolved
        
        try:
            collections_json = self._run_bw_command(['list', 'collections'])
            collections = json.loads(collections_json)
            logging.debug(f"Found {len(collections)} collections")
            
            # Reconstruct the full path to try different combinations
            full_path = '/'.join(path_parts)
            
            for collection in collections:
                collection_name = collection.get('name', '')
                collection_id = collection.get('id')
                collection_org_id = collection.get('organizationId')
                
                # Only consider collections that belong to our organization
                if collection_org_id == org_id and collection_name and collection_id:
                    # Try exact match with full path first
                    if collection_name == full_path:
                        resolved[collection_name] = collection_id
                        logging.debug(f"Resolved collection (exact match) '{collection_name}' to ID: {collection_id}")
                    # Also try individual parts
                    elif collection_name in path_parts:
                        resolved[collection_name] = collection_id
                        logging.debug(f"Resolved collection (partial match) '{collection_name}' to ID: {collection_id}")
                        
        except Exception as e:
            logging.debug(f"Failed to list collections: {e}")
        
        return resolved
    
    def _item_matches_constraints(self, item: Dict, org_id: Optional[str], path_constraints: Dict[str, str]) -> bool:
        """Check if an item matches the organization and path constraints"""
        # Check organization match
        item_org_id = item.get('organizationId')
        if org_id != item_org_id:
            logging.debug(f"Organization mismatch: expected {org_id}, got {item_org_id}")
            return False
        
        # If no path constraints, we're done
        if not path_constraints:
            logging.debug("No path constraints to check")
            return True
        
        # Check folder/collection constraints
        item_folder_id = item.get('folderId')
        item_collection_ids = set(item.get('collectionIds', []))
        constraint_ids = set(path_constraints.values())
        
        # Item matches if its folder or any of its collections match our constraints
        if item_folder_id and item_folder_id in constraint_ids:
            logging.debug(f"Item folder {item_folder_id} matches constraints")
            return True
        
        if item_collection_ids.intersection(constraint_ids):
            matching_collections = item_collection_ids.intersection(constraint_ids)
            logging.debug(f"Item collections {matching_collections} match constraints")
            return True
        
        logging.debug(f"Item folder/collections do not match path constraints")
        return False
    
    def resolve_bw_uri_to_value(self, uri: str) -> str:
        """Resolve a complete bw:// URI to its field value using step-by-step resolution"""
        logging.debug(f"Starting bw:// URI resolution: {uri}")
        
        # Remove bw:// prefix and split into parts
        if not uri.startswith('bw://'):
            raise ValueError(f"Invalid bw:// URI: {uri}")
        
        path_part = uri[5:]  # Remove bw://
        parts = path_part.split('/')
        if len(parts) < 3:
            raise ValueError(f"bw:// URI must have at least org/item/field: {uri}")
        
        org_or_vault = parts[0]
        remaining_parts = parts[1:]  # Everything after org
        
        logging.debug(f"Org/vault: {org_or_vault}, remaining parts: {remaining_parts}")
        
        # Step 1: Resolve organization
        org_id = self._resolve_organization(org_or_vault)
        logging.debug(f"Resolved organization '{org_or_vault}' to ID: {org_id}")
        
        # Step 2: Find constraints (folders/collections) and locate item
        # We'll try different combinations of path parts to find the item
        item, field_name = self._find_item_with_field_from_parts(org_id, remaining_parts)
        
        if not item:
            raise ValueError(f"No item found for bw:// URI: {uri}")
        
        # Step 4: Get the field value
        value = self.get_field_value(item, field_name)
        if value is None:
            raise ValueError(f"Field '{field_name}' not found in item '{item.get('name')}'")
        
        return value
    
    def _find_item_with_field_from_parts(self, org_id: Optional[str], parts: List[str]) -> Tuple[Optional[Dict], str]:
        """Try different combinations of parts to find an item with the field"""
        logging.debug(f"Searching for item with org_id={org_id} and parts={parts}")
        
        if self.sync:
            self.sync_vault()
        
        # Get all items
        items_json = self._run_bw_command(['list', 'items'])
        items = json.loads(items_json)
        logging.debug(f"Found {len(items)} total items to search")
        
        # Filter items by organization first
        candidate_items = []
        for item in items:
            item_org_id = item.get('organizationId')
            if org_id == item_org_id:  # This handles both None==None and uuid==uuid
                candidate_items.append(item)
        
        logging.debug(f"Found {len(candidate_items)} items matching organization constraint")
        
        # Try different splits of parts to find item_name + field_name
        # Work backwards: last part is always field, second-to-last might be item name
        for split_point in range(1, len(parts)):  # Try different split points
            potential_item_name = parts[split_point - 1]
            potential_field_name = '/'.join(parts[split_point:])
            
            logging.debug(f"Trying item_name='{potential_item_name}', field_name='{potential_field_name}'")
            
            # Look for this item name in our candidates
            for item in candidate_items:
                if item.get('name') == potential_item_name:
                    logging.debug(f"Found potential item match: {potential_item_name}")
                    
                    # Check if this item has the field
                    if self.get_field_value(item, potential_field_name) is not None:
                        logging.debug(f"Item has field '{potential_field_name}' - match found!")
                        return item, potential_field_name
                    else:
                        logging.debug(f"Item does not have field '{potential_field_name}' - continuing search")
        
        logging.debug("No matching item found")
        return None, ""


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
        logging.debug(f"Value preview: {value[:50]}{'...' if len(value) > 50 else ''}")
        return value
    
    def _resolve_bw_uri(self, uri: str) -> str:
        """Resolve a bw:// URI to its secret value"""
        if not URIParser.is_bw_uri(uri):
            logging.debug(f"Invalid bw:// URI format: {uri}")
            raise BWEnvError(f"Invalid bw:// URI format: {uri}")
        
        logging.debug(f"Resolving bw:// URI: {uri}")
        
        # The actual parsing and resolution will be handled by find_item_by_bw_uri
        # which will do the step-by-step org/collection/folder resolution
        try:
            value = self.bw_client.resolve_bw_uri_to_value(uri)
            logging.debug(f"Successfully resolved bw:// URI {uri} to value (length: {len(value)} chars)")
            logging.debug(f"Value preview: {value[:50]}{'...' if len(value) > 50 else ''}")
            return value
        except Exception as e:
            logging.debug(f"Failed to resolve bw:// URI {uri}: {e}")
            raise BWEnvError(f"Failed to resolve bw:// URI {uri}: {e}")
    
    def create_resolved_environment(self) -> Dict[str, str]:
        """Create a new environment with all supported URIs resolved"""
        logging.debug("Creating resolved environment...")
        logging.debug(f"Starting with {len(os.environ)} environment variables")
        new_env = os.environ.copy()
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
    """Run a command with resolved environment variables"""
    logging.debug(f"Running command: {' '.join(args.cmd_args)}")
    logging.debug(f"Sync enabled: {not args.no_sync}")
    logging.debug(f"Command arguments count: {len(args.cmd_args)}")
    
    bw_client = BitwardenClient(no_sync=args.no_sync)
    processor = EnvironmentProcessor(bw_client)
    
    resolved_env = processor.create_resolved_environment()
    
    try:
        logging.debug(f"Executing command with {len(resolved_env)} environment variables")
        uri_vars = processor.scan_environment()
        logging.debug(f"Resolved variables with supported URIs: {[k for k in resolved_env.keys() if k in uri_vars]}")
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
    logging.debug(f"URI validation - op://: {URIParser.is_op_uri(args.uri)}, bw://: {URIParser.is_bw_uri(args.uri)}")
    
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
    
    # Manual parsing to handle --debug and --no-sync flags in any position
    debug = False
    no_sync = False
    command = None
    uri = None
    cmd_args = None
    
    # Find '--' separator if it exists after 'run' command
    separator_idx = None
    run_idx = None
    
    # Find the '--' separator first to know where we can extract flags from
    separator_idx = None
    run_command_idx = None
    for i, arg in enumerate(argv):
        if arg == '--':
            separator_idx = i
        elif arg == 'run':
            run_command_idx = i
    
    # Validate that if '--' exists, it should come after 'run'
    if separator_idx is not None and run_command_idx is not None and separator_idx < run_command_idx:
        print("Error: '--' separator must come after 'run' command", file=sys.stderr)
        sys.exit(1)
    
    # Only extract flags before the '--' separator (if it exists)
    flag_extraction_limit = separator_idx if separator_idx is not None else len(argv)
    
    # First pass: extract global flags and find command structure
    filtered_argv = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if i < flag_extraction_limit and arg == '--debug':
            debug = True
        elif i < flag_extraction_limit and arg == '--no-sync':
            no_sync = True
        elif arg in ['run', 'read']:
            command = arg
            if command == 'run':
                run_idx = len(filtered_argv)  # Position in filtered argv
            filtered_argv.append(arg)
        else:
            filtered_argv.append(arg)
        i += 1
    
    argv = filtered_argv
    
    # Update separator_idx in the filtered argv
    if separator_idx is not None:
        # Find the new position of '--' in filtered argv
        separator_idx = None
        for i, arg in enumerate(argv):
            if arg == '--':
                separator_idx = i
                break
    
    if separator_idx is not None:
        # Split arguments at '--'
        bwenv_args = argv[:separator_idx]
        cmd_args = argv[separator_idx + 1:]
    else:
        # No '--' found, use original behavior
        bwenv_args = argv
        if command == 'run' and len(bwenv_args) > 1:
            # Everything after 'run' is cmd_args
            cmd_args = bwenv_args[1:]
            bwenv_args = bwenv_args[:1]  # Just keep 'run'
    
    # Parse remaining arguments with argparse
    parser = argparse.ArgumentParser(
        description="Bitwarden Environment Variable Processor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Run command
    run_parser = subparsers.add_parser('run', help='Run a command with resolved environment variables')
    
    # Read command
    read_parser = subparsers.add_parser('read', help='Read a specific secret value')
    read_parser.add_argument('uri', help='URI to read (e.g., op://Employee/example/secret)')
    
    args = parser.parse_args(bwenv_args)
    
    # Set the manually parsed flags
    args.debug = debug
    args.no_sync = no_sync
    
    # Set cmd_args for run command
    if args.command == 'run':
        args.cmd_args = cmd_args or []
    
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