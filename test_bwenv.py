#!/usr/bin/env python3
"""
Unit tests for bwenv script
"""

import argparse
import base64
import datetime
import io
import json
import logging
import os
import subprocess
import unittest
from unittest.mock import Mock, patch
import sys

# Add the script directory to Python path to import bwenv modules
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

# Import the bwenv module
import bwenv

# Never open a real password dialog from the tests; dialog tests opt back in explicitly
os.environ.setdefault('BWENV_PROMPT', 'tty')


def fake_bw(responses):
    """A subprocess.run side effect that behaves like the bw CLI.

    responses maps an argv tuple to stdout, or to (returncode, stdout, stderr). `bw status` defaults
    to unlocked; anything else unlisted succeeds with empty-list JSON.
    """
    def run(command, **kwargs):
        response = responses.get(tuple(command))
        if response is None:
            response = '{"status":"unlocked"}' if list(command) == ['bw', 'status'] else '[]'
        returncode, stdout, stderr = response if isinstance(response, tuple) else (0, response, '')
        return Mock(stdout=stdout, stderr=stderr, returncode=returncode)
    return run


class TestURIParser(unittest.TestCase):
    """Test cases for URI parsing functionality"""
    
    def test_valid_simple_uri(self):
        """Test parsing a simple valid URI"""
        uri = "op://Employee/example/secret"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertEqual(result, ("Employee", "example", "secret"))
    
    def test_valid_complex_uri(self):
        """Test parsing URI with complex keyname containing slashes"""
        uri = "op://Employee/example/Prod/access_token"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertEqual(result, ("Employee", "example", "Prod/access_token"))
    
    def test_valid_uri_with_spaces(self):
        """Test parsing URI with spaces in vault and item names"""
        uri = "op://My Vault/My Item/my_key"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertEqual(result, ("My Vault", "My Item", "my_key"))
    
    def test_valid_uri_deep_keyname(self):
        """Test parsing URI with deeply nested keyname"""
        uri = "op://employee/application/this/is/a/really/long/key"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertEqual(result, ("employee", "application", "this/is/a/really/long/key"))
    
    def test_invalid_uri_no_scheme(self):
        """Test parsing invalid URI without op:// scheme"""
        uri = "Employee/example/secret"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertIsNone(result)
    
    def test_invalid_uri_wrong_scheme(self):
        """Test parsing invalid URI with wrong scheme"""
        uri = "https://Employee/example/secret"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertIsNone(result)
    
    def test_invalid_uri_missing_parts(self):
        """Test parsing invalid URI missing required parts"""
        uri = "op://Employee/example"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertIsNone(result)
    
    def test_invalid_uri_empty_parts(self):
        """Test parsing invalid URI with empty parts"""
        uri = "op:///example/secret"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertIsNone(result)
    
    def test_is_op_uri_valid(self):
        """Test is_op_uri with valid URIs"""
        self.assertTrue(bwenv.URIParser.is_op_uri("op://Employee/example/secret"))
        self.assertTrue(bwenv.URIParser.is_op_uri("op://My Vault/My Item/key"))
    
    def test_is_op_uri_invalid(self):
        """Test is_op_uri with invalid URIs"""
        self.assertFalse(bwenv.URIParser.is_op_uri("not-a-uri"))
        self.assertFalse(bwenv.URIParser.is_op_uri("https://example.com"))
        self.assertFalse(bwenv.URIParser.is_op_uri("op://incomplete"))
    
    def test_valid_demo_data_uri(self):
        """Test parsing Demo Data URI with spaces"""
        uri = "op://Demo Data/demo/prod/plaintext"
        result = bwenv.URIParser.parse_op_uri(uri)
        self.assertEqual(result, ("Demo Data", "demo", "prod/plaintext"))
    
    def test_parse_bw_uri_valid(self):
        """Test parsing valid bw:// URIs"""
        # Basic bw:// URI
        uri = "bw://myvault/Demo/Data/DEMO_DATA/username"
        result = bwenv.URIParser.parse_bw_uri(uri)
        self.assertEqual(result, uri)  # Should return the URI itself if valid
        
        # UUID format
        uri = "bw://7e6ff908-4315-4377-9834-7154889cb4c8/28957e48-d900-4f14-a694-538bdb9654ce/DEMO_DATA/prod/plaintext"
        result = bwenv.URIParser.parse_bw_uri(uri)
        self.assertEqual(result, uri)  # Should return the URI itself if valid
    
    def test_parse_bw_uri_with_org_name(self):
        """Test parsing bw:// URIs with an organization name (spaces and dots included)"""
        uri = "bw://Example Org.fm/Demo/Data/DEMO_DATA/password"
        result = bwenv.URIParser.parse_bw_uri(uri)
        self.assertEqual(result, uri)  # Should return the URI itself if valid
    
    def test_parse_bw_uri_invalid(self):
        """Test parsing invalid bw:// URIs"""
        # Missing parts
        uri = "bw://myvault/Demo"
        result = bwenv.URIParser.parse_bw_uri(uri)
        self.assertIsNone(result)
        
        # Wrong scheme
        uri = "op://myvault/Demo/Data/DEMO_DATA/username"
        result = bwenv.URIParser.parse_bw_uri(uri)
        self.assertIsNone(result)
    
    def test_is_bw_uri_valid(self):
        """Test is_bw_uri with valid URIs"""
        self.assertTrue(bwenv.URIParser.is_bw_uri("bw://myvault/Demo/Data/DEMO_DATA/username"))
        self.assertTrue(bwenv.URIParser.is_bw_uri("bw://someorg/Demo/Data/DEMO_DATA/password"))
    
    def test_is_bw_uri_invalid(self):
        """Test is_bw_uri with invalid URIs"""
        self.assertFalse(bwenv.URIParser.is_bw_uri("not-a-uri"))
        self.assertFalse(bwenv.URIParser.is_bw_uri("op://Employee/example/secret"))
        self.assertFalse(bwenv.URIParser.is_bw_uri("bw://incomplete"))
    
    def test_is_supported_uri(self):
        """Test is_supported_uri with various URI formats"""
        # op:// URIs
        self.assertTrue(bwenv.URIParser.is_supported_uri("op://Employee/example/secret"))
        self.assertTrue(bwenv.URIParser.is_supported_uri("op://Demo Data/demo/prod/plaintext"))
        
        # bw:// URIs
        self.assertTrue(bwenv.URIParser.is_supported_uri("bw://myvault/Demo/Data/DEMO_DATA/username"))
        self.assertTrue(bwenv.URIParser.is_supported_uri("bw://someorg/Demo/Data/DEMO_DATA/password"))
        
        # Invalid URIs
        self.assertFalse(bwenv.URIParser.is_supported_uri("not-a-uri"))
        self.assertFalse(bwenv.URIParser.is_supported_uri("https://example.com"))
    
    def test_parse_uri_backward_compatibility(self):
        """Test that parse_uri still works for backward compatibility"""
        uri = "op://Employee/example/secret"
        result = bwenv.URIParser.parse_uri(uri)
        self.assertEqual(result, ("Employee", "example", "secret"))


class TestBitwardenClient(unittest.TestCase):
    """Test cases for Bitwarden CLI client"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.sample_items = [
            {
                "id": "item1",
                "name": "Test Item 1",
                "login": {
                    "username": "testuser",
                    "password": "testpass",
                    "uris": [
                        {"uri": "op://Employee/example"}
                    ]
                },
                "fields": [
                    {"name": "secret", "value": "secret_value"},
                    {"name": "Prod/access_token", "value": "token_123"}
                ]
            },
            {
                "id": "item2",
                "name": "Test Item 2",
                "login": {
                    "username": "user2",
                    "password": "pass2",
                    "uris": [
                        {"uri": "https://example.com"}
                    ]
                }
            },
            {
                "id": "item3",
                "name": "Test Item 3",
                "login": {
                    "username": "user3",
                    "password": "pass3",
                    "uris": [
                        {"uri": "op://My Vault/My Item"}
                    ]
                },
                "fields": [
                    {"name": "api_key", "value": "key_456"}
                ]
            }
        ]
    
    def _commands(self, mock_run):
        return [c[0][0] for c in mock_run.call_args_list]

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_run_bw_command_success(self, mock_run):
        """A command runs after one status check, with the session, a timeout and UTF-8 decoding"""
        mock_run.side_effect = fake_bw({('bw', 'list', 'items'): 'test output'})

        client = bwenv.BitwardenClient()
        result = client._run_bw_command(['list', 'items'])

        self.assertEqual(result, "test output")
        self.assertEqual(self._commands(mock_run), [['bw', 'status'], ['bw', 'list', 'items']])
        for call in mock_run.call_args_list:
            self.assertEqual(call[1]['env']['BW_SESSION'], 'test_session_token')
            self.assertEqual(call[1]['encoding'], 'utf-8')
            self.assertGreater(call[1]['timeout'], 0)

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_run_bw_command_failure(self, mock_run):
        """A failing bw command raises BWEnvError carrying bw's stderr"""
        mock_run.side_effect = fake_bw({('bw', 'list', 'items'): (1, '', 'Authentication required')})

        client = bwenv.BitwardenClient()
        with self.assertRaises(bwenv.BWEnvError) as cm:
            client._run_bw_command(['list', 'items'])

        self.assertIn("Authentication required", str(cm.exception))

    @patch('subprocess.run')
    def test_run_bw_command_not_found(self, mock_run):
        """Test Bitwarden CLI not found"""
        mock_run.side_effect = FileNotFoundError()

        client = bwenv.BitwardenClient()
        with self.assertRaises(bwenv.BWEnvError) as cm:
            client._run_bw_command(['list', 'items'])

        self.assertIn("not found", str(cm.exception))

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_hung_bw_times_out(self, mock_run):
        """A bw call that hangs (e.g. the server is unreachable) becomes a BWEnvError, not a hang"""
        mock_run.side_effect = subprocess.TimeoutExpired(['bw', 'status'], 120)

        client = bwenv.BitwardenClient()
        with self.assertRaises(bwenv.BWEnvError) as cm:
            client._run_bw_command(['list', 'items'])

        self.assertIn("BWENV_TIMEOUT", str(cm.exception))

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token', 'BWENV_TIMEOUT': '5'})
    def test_timeout_is_configurable(self, mock_run):
        """BWENV_TIMEOUT sets the timeout passed to bw"""
        mock_run.side_effect = fake_bw({})

        bwenv.BitwardenClient()._run_bw_command(['list', 'items'])

        self.assertEqual({c[1]['timeout'] for c in mock_run.call_args_list}, {5.0})

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_status_checked_once_per_client(self, mock_run):
        """bw status runs once per client, not before every command"""
        mock_run.side_effect = fake_bw({})

        client = bwenv.BitwardenClient()
        client._run_bw_command(['sync'])
        client._run_bw_command(['list', 'items'])
        client._run_bw_command(['list', 'folders'])

        self.assertEqual(self._commands(mock_run).count(['bw', 'status']), 1)

    @patch('subprocess.run')
    def test_unauthenticated_is_an_error(self, mock_run):
        """Not being logged in gives a clear error and runs nothing else"""
        mock_run.side_effect = fake_bw({('bw', 'status'): '{"status":"unauthenticated"}'})

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient()._run_bw_command(['list', 'items'])

        self.assertIn("not logged in", str(cm.exception))
        self.assertEqual(self._commands(mock_run), [['bw', 'status']])

    @patch('sys.stdin')
    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'stale_session_token'})
    def test_locked_vault_unlocks_once_on_a_terminal(self, mock_run, mock_stdin):
        """A locked vault is unlocked once; the new session is used without touching os.environ"""
        mock_stdin.isatty.return_value = True
        mock_run.side_effect = fake_bw({
            ('bw', 'status'): '{"status":"locked"}',
            ('bw', 'unlock', '--raw'): 'new_session_token_123',
        })

        client = bwenv.BitwardenClient()
        client._run_bw_command(['list', 'items'])
        client._run_bw_command(['list', 'folders'])

        self.assertEqual(self._commands(mock_run).count(['bw', 'unlock', '--raw']), 1)
        list_calls = [c for c in mock_run.call_args_list if c[0][0][:2] == ['bw', 'list']]
        self.assertTrue(all(c[1]['env']['BW_SESSION'] == 'new_session_token_123' for c in list_calls))
        self.assertEqual(os.environ['BW_SESSION'], 'stale_session_token')

    @patch('sys.stdin')
    @patch('subprocess.run')
    @patch.dict(os.environ, {}, clear=False)
    def test_locked_vault_without_terminal_does_not_prompt(self, mock_run, mock_stdin):
        """With no terminal (piped stdin, CI), bwenv never runs bw unlock - piped data is not a password"""
        os.environ.pop('BW_SESSION', None)
        mock_stdin.isatty.return_value = False
        mock_run.side_effect = fake_bw({('bw', 'status'): '{"status":"locked"}'})

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient()._run_bw_command(['list', 'items'])

        self.assertIn("BW_SESSION", str(cm.exception))
        self.assertNotIn(['bw', 'unlock', '--raw'], self._commands(mock_run))

    @patch('sys.stdin')
    @patch('subprocess.run')
    def test_failed_unlock_prompts_once_with_a_reason(self, mock_run, mock_stdin):
        """A wrong master password gives one prompt and a non-empty error"""
        mock_stdin.isatty.return_value = True
        mock_run.side_effect = fake_bw({
            ('bw', 'status'): '{"status":"locked"}',
            ('bw', 'unlock', '--raw'): (1, '', ''),
        })

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient()._run_bw_command(['list', 'items'])

        self.assertIn("unlock", str(cm.exception))
        self.assertEqual(self._commands(mock_run).count(['bw', 'unlock', '--raw']), 1)
        self.assertNotIn(['bw', 'list', 'items'], self._commands(mock_run))

    @patch('shutil.which', return_value='C:\\npm\\bw.cmd')
    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_windows_finds_npm_installed_bw(self, mock_run, mock_which):
        """On Windows, bw is resolved through PATHEXT (bw.cmd), which CreateProcess does not do itself"""
        mock_run.side_effect = fake_bw({})
        with patch.object(bwenv, 'IS_WINDOWS', True):
            bwenv.BitwardenClient()._run_bw_command(['list', 'items'])

        self.assertTrue(all(c[0][0][0] == 'C:\\npm\\bw.cmd' for c in mock_run.call_args_list))

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_sync_vault(self, mock_run):
        """Test vault synchronization"""
        mock_run.side_effect = fake_bw({})

        bwenv.BitwardenClient().sync_vault()

        self.assertEqual(self._commands(mock_run), [['bw', 'status'], ['bw', 'sync']])

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_get_items_with_op_uris(self, mock_run):
        """Test filtering items with op:// URIs"""
        # Use a function to determine return value based on command
        def mock_command_response(command, **kwargs):
            if command == ['bw', 'status']:
                return Mock(stdout='{"status":"unlocked"}', returncode=0)
            elif command == ['bw', 'sync']:
                return Mock(stdout="Syncing complete.", returncode=0)
            elif command == ['bw', 'list', 'items']:
                return Mock(stdout=json.dumps(self.sample_items), returncode=0)
            else:
                return Mock(stdout="", returncode=0)
        
        mock_run.side_effect = mock_command_response
        
        client = bwenv.BitwardenClient()
        items = client.get_items_with_op_uris()
        
        # Should return only items 1 and 3 (those with op:// URIs)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]['id'], 'item1')
        self.assertEqual(items[1]['id'], 'item3')
    
    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_get_items_with_sync(self, mock_run):
        """Test getting items with sync enabled"""
        # Use a function to determine return value based on command
        def mock_command_response(command, **kwargs):
            if command == ['bw', 'status']:
                return Mock(stdout='{"status":"unlocked"}', returncode=0)
            elif command == ['bw', 'sync']:
                return Mock(stdout="Syncing complete.", returncode=0)
            elif command == ['bw', 'list', 'items']:
                return Mock(stdout=json.dumps(self.sample_items), returncode=0)
            else:
                return Mock(stdout="", returncode=0)
        
        mock_run.side_effect = mock_command_response
        
        client = bwenv.BitwardenClient(no_sync=False)
        items = client.get_items_with_op_uris()
        
        # Should call status validation, sync, then list items
        self.assertEqual([c[0][0] for c in mock_run.call_args_list],
                         [['bw', 'status'], ['bw', 'sync'], ['bw', 'list', 'items']])
    
    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_find_item_by_uri_prefix(self, mock_run):
        """Test finding item by URI prefix"""
        # Use a function to determine return value based on command
        def mock_command_response(command, **kwargs):
            if command == ['bw', 'status']:
                return Mock(stdout='{"status":"unlocked"}', returncode=0)
            elif command == ['bw', 'sync']:
                return Mock(stdout="Syncing complete.", returncode=0)
            elif command == ['bw', 'list', 'items']:
                return Mock(stdout=json.dumps(self.sample_items), returncode=0)
            else:
                return Mock(stdout="", returncode=0)
        
        mock_run.side_effect = mock_command_response
        
        client = bwenv.BitwardenClient()
        
        # Find existing item
        item = client.find_item_by_uri_prefix("Employee", "example")
        self.assertIsNotNone(item)
        self.assertEqual(item['id'], 'item1')
        
        # Try to find non-existing item - this uses the cache so shouldn't trigger more calls
        item = client.find_item_by_uri_prefix("NonExistent", "item")
        self.assertIsNone(item)

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_bw_uri_items_cached_across_lookups(self, mock_run):
        """Test that several bw:// lookups sync and list items only once"""
        def mock_command_response(command, **kwargs):
            if command == ['bw', 'status']:
                return Mock(stdout='{"status":"unlocked"}', returncode=0)
            elif command == ['bw', 'sync']:
                return Mock(stdout="Syncing complete.", returncode=0)
            elif command == ['bw', 'list', 'items']:
                return Mock(stdout=json.dumps(self.sample_items), returncode=0)
            else:
                return Mock(stdout="[]", returncode=0)

        mock_run.side_effect = mock_command_response

        client = bwenv.BitwardenClient()
        self.assertEqual(client.resolve_bw_uri_to_value('bw://myvault/Test Item 1/secret'), 'secret_value')
        self.assertEqual(client.resolve_bw_uri_to_value('bw://myvault/Test Item 1/username'), 'testuser')

        commands = [c[0][0] for c in mock_run.call_args_list]
        self.assertEqual(commands.count(['bw', 'sync']), 1)
        self.assertEqual(commands.count(['bw', 'list', 'items']), 1)

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_op_uris_found_when_bw_search_ignores_uris(self, mock_run):
        """op:// items are found by filtering all items locally, not via `bw list items --search`.

        bw 2026.9.1's --search no longer matches website URIs, so searching for 'op://' returns nothing.
        """
        def mock_command_response(command, **kwargs):
            if command == ['bw', 'status']:
                return Mock(stdout='{"status":"unlocked"}', returncode=0)
            elif command == ['bw', 'list', 'items']:
                return Mock(stdout=json.dumps(self.sample_items), returncode=0)
            else:  # including any `--search` call: behave like the current bw CLI
                return Mock(stdout="[]", returncode=0)

        mock_run.side_effect = mock_command_response

        client = bwenv.BitwardenClient(no_sync=True)
        item = client.find_item_by_uri_prefix("Employee", "example")
        self.assertIsNotNone(item)
        self.assertEqual(item['id'], 'item1')

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_op_and_bw_uris_share_one_item_fetch(self, mock_run):
        """Mixing op:// and bw:// lookups syncs and lists items only once"""
        def mock_command_response(command, **kwargs):
            if command == ['bw', 'status']:
                return Mock(stdout='{"status":"unlocked"}', returncode=0)
            elif command == ['bw', 'sync']:
                return Mock(stdout="Syncing complete.", returncode=0)
            elif command == ['bw', 'list', 'items']:
                return Mock(stdout=json.dumps(self.sample_items), returncode=0)
            else:
                return Mock(stdout="[]", returncode=0)

        mock_run.side_effect = mock_command_response

        client = bwenv.BitwardenClient()
        self.assertIsNotNone(client.find_item_by_uri_prefix("Employee", "example"))
        self.assertEqual(client.resolve_bw_uri_to_value('bw://myvault/Test Item 1/secret'), 'secret_value')
        self.assertIsNotNone(client.find_item_by_uri_prefix("Employee", "example"))

        commands = [c[0][0] for c in mock_run.call_args_list]
        self.assertEqual(commands.count(['bw', 'sync']), 1)
        self.assertEqual(commands.count(['bw', 'list', 'items']), 1)

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_organizations_cached_across_lookups(self, mock_run):
        """Test that resolving organization names lists organizations only once"""
        organizations = [{"id": "org-uuid-1", "name": "Example Org"}]

        def mock_command_response(command, **kwargs):
            if command == ['bw', 'status']:
                return Mock(stdout='{"status":"unlocked"}', returncode=0)
            elif command == ['bw', 'list', 'organizations']:
                return Mock(stdout=json.dumps(organizations), returncode=0)
            else:
                return Mock(stdout="[]", returncode=0)

        mock_run.side_effect = mock_command_response

        client = bwenv.BitwardenClient()
        self.assertEqual(client._resolve_organization('Example Org'), 'org-uuid-1')
        self.assertEqual(client._resolve_organization('Example Org'), 'org-uuid-1')
        self.assertIsNone(client._resolve_organization('myvault'))

        commands = [c[0][0] for c in mock_run.call_args_list]
        self.assertEqual(commands.count(['bw', 'list', 'organizations']), 1)


    def test_get_field_value_custom_field(self):
        """Test getting value from custom field"""
        client = bwenv.BitwardenClient()
        item = self.sample_items[0]
        
        # Get simple custom field
        value = client.get_field_value(item, "secret")
        self.assertEqual(value, "secret_value")
        
        # Get nested custom field
        value = client.get_field_value(item, "Prod/access_token")
        self.assertEqual(value, "token_123")
    
    def test_get_field_value_login_fields(self):
        """Test getting value from login fields"""
        client = bwenv.BitwardenClient()
        item = self.sample_items[0]
        
        # Get username
        value = client.get_field_value(item, "username")
        self.assertEqual(value, "testuser")
        
        # Get password
        value = client.get_field_value(item, "password")
        self.assertEqual(value, "testpass")
    
    def test_get_field_value_not_found(self):
        """Test getting non-existent field value"""
        client = bwenv.BitwardenClient()
        item = self.sample_items[0]
        
        value = client.get_field_value(item, "nonexistent")
        self.assertIsNone(value)


class TestBwUriPathResolution(unittest.TestCase):
    """Test that the folder/collection part of a bw:// URI selects the item"""

    ORG_ID = "org-uuid-1"
    FOLDERS = [
        {"id": "folder-prod", "name": "Prod"},
        {"id": "folder-dev", "name": "Dev"},
    ]
    COLLECTIONS = [
        {"id": "coll-demo-data", "name": "Demo/Data", "organizationId": ORG_ID},
        {"id": "coll-other", "name": "Other", "organizationId": ORG_ID},
    ]
    ORGANIZATIONS = [{"id": ORG_ID, "name": "Example Org"}]
    ITEMS = [
        {"id": "p1", "name": "DEMO_DATA", "organizationId": None, "folderId": "folder-prod",
         "fields": [{"name": "secret", "value": "PROD-VALUE"}]},
        {"id": "p2", "name": "DEMO_DATA", "organizationId": None, "folderId": "folder-dev",
         "fields": [{"name": "secret", "value": "DEV-VALUE"}]},
        {"id": "p3", "name": "ONLY_ONE", "organizationId": None, "folderId": "folder-dev",
         "fields": [{"name": "prod/plaintext", "value": "A Dummy String"}]},
        {"id": "o1", "name": "DEMO_DATA", "organizationId": ORG_ID, "collectionIds": ["coll-demo-data"],
         "fields": [{"name": "secret", "value": "ORG-DEMO-VALUE"}]},
        {"id": "o2", "name": "DEMO_DATA", "organizationId": ORG_ID, "collectionIds": ["coll-other"],
         "fields": [{"name": "secret", "value": "ORG-OTHER-VALUE"}]},
    ]

    def setUp(self):
        responses = {
            ('bw', 'status'): '{"status":"unlocked"}',
            ('bw', 'sync'): 'Syncing complete.',
            ('bw', 'list', 'items'): json.dumps(self.ITEMS),
            ('bw', 'list', 'folders'): json.dumps(self.FOLDERS),
            ('bw', 'list', 'collections'): json.dumps(self.COLLECTIONS),
            ('bw', 'list', 'organizations'): json.dumps(self.ORGANIZATIONS),
        }
        patcher = patch('subprocess.run',
                        side_effect=lambda command, **kwargs: Mock(stdout=responses.get(tuple(command), "[]"),
                                                                   returncode=0))
        self.mock_run = patcher.start()
        self.addCleanup(patcher.stop)
        env_patcher = patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        self.client = bwenv.BitwardenClient()

    def test_folder_selects_item(self):
        """Same-named personal items are told apart by folder"""
        self.assertEqual(self.client.resolve_bw_uri_to_value('bw://myvault/Dev/DEMO_DATA/secret'), 'DEV-VALUE')
        self.assertEqual(self.client.resolve_bw_uri_to_value('bw://myvault/Prod/DEMO_DATA/secret'), 'PROD-VALUE')

    def test_folder_by_uuid(self):
        """A folder can be given by UUID instead of name"""
        self.assertEqual(self.client.resolve_bw_uri_to_value('bw://myvault/folder-dev/DEMO_DATA/secret'), 'DEV-VALUE')

    def test_unknown_folder_is_not_found(self):
        """A folder that does not exist must not fall back to any same-named item"""
        with self.assertRaises(bwenv.BWEnvError):
            self.client.resolve_bw_uri_to_value('bw://myvault/Nonexistent/DEMO_DATA/secret')

    def test_nested_collection_selects_item(self):
        """A nested collection name (with '/') selects the organization item"""
        self.assertEqual(self.client.resolve_bw_uri_to_value('bw://Example Org/Demo/Data/DEMO_DATA/secret'),
                         'ORG-DEMO-VALUE')
        self.assertEqual(self.client.resolve_bw_uri_to_value('bw://Example Org/Other/DEMO_DATA/secret'),
                         'ORG-OTHER-VALUE')

    def test_partial_collection_name_is_not_a_match(self):
        """Only the full collection name matches, not one segment of it"""
        with self.assertRaises(bwenv.BWEnvError):
            self.client.resolve_bw_uri_to_value('bw://Example Org/Data/DEMO_DATA/secret')

    def test_ambiguous_item_without_path_is_an_error(self):
        """Without a path, two distinct items with the same name must not be picked silently"""
        with self.assertRaises(bwenv.BWEnvError) as ctx:
            self.client.resolve_bw_uri_to_value('bw://myvault/DEMO_DATA/secret')
        self.assertIn('DEMO_DATA', str(ctx.exception))

    def test_unique_item_without_path_still_resolves(self):
        """A uniquely named item resolves without a path, and slashes stay in the field name"""
        self.assertEqual(self.client.resolve_bw_uri_to_value('bw://myvault/ONLY_ONE/prod/plaintext'),
                         'A Dummy String')

    def test_folders_and_collections_listed_once(self):
        """Folder and collection lists are cached across lookups"""
        self.client.resolve_bw_uri_to_value('bw://myvault/Dev/DEMO_DATA/secret')
        self.client.resolve_bw_uri_to_value('bw://myvault/Prod/DEMO_DATA/secret')
        self.client.resolve_bw_uri_to_value('bw://Example Org/Demo/Data/DEMO_DATA/secret')
        self.client.resolve_bw_uri_to_value('bw://Example Org/Other/DEMO_DATA/secret')
        commands = [c[0][0] for c in self.mock_run.call_args_list]
        self.assertEqual(commands.count(['bw', 'list', 'folders']), 1)
        self.assertEqual(commands.count(['bw', 'list', 'collections']), 1)



class TestPasswordDialog(unittest.TestCase):
    """Choosing and driving the desktop password dialog"""

    def _which(self, *available):
        return lambda name: f'/usr/bin/{name}' if name in available else None

    def test_macos_uses_osascript_with_hidden_answer(self):
        with patch.object(bwenv.sys, 'platform', 'darwin'), patch('shutil.which', self._which('osascript')):
            command = bwenv.password_dialog_command('Master password:')
        self.assertEqual(command[:2], ['/usr/bin/osascript', '-e'])
        self.assertIn('with hidden answer', command[2])
        self.assertIn('"Master password:"', command[2])

    def test_windows_uses_a_masked_powershell_form(self):
        with patch.object(bwenv, 'IS_WINDOWS', True), patch.object(bwenv.sys, 'platform', 'win32'), \
                patch('shutil.which', self._which('powershell')):
            command = bwenv.password_dialog_command("Master password, it's needed:")
        self.assertEqual(command[0], '/usr/bin/powershell')
        self.assertIn('UseSystemPasswordChar', command[-1])
        self.assertIn("'Master password, it''s needed:'", command[-1])  # single quotes escaped

    @patch.dict(os.environ, {'XDG_CURRENT_DESKTOP': 'KDE', 'DISPLAY': ':0'})
    def test_kde_prefers_kdialog(self):
        with patch.object(bwenv, 'IS_WINDOWS', False), patch.object(bwenv.sys, 'platform', 'linux'), \
                patch('shutil.which', self._which('kdialog', 'zenity')):
            command = bwenv.password_dialog_command('Master password:')
        self.assertEqual(command, ['/usr/bin/kdialog', '--title', 'bwenv', '--password', 'Master password:'])

    @patch.dict(os.environ, {'XDG_CURRENT_DESKTOP': 'GNOME', 'WAYLAND_DISPLAY': 'wayland-0'})
    def test_other_desktops_prefer_zenity(self):
        with patch.object(bwenv, 'IS_WINDOWS', False), patch.object(bwenv.sys, 'platform', 'linux'), \
                patch('shutil.which', self._which('kdialog', 'zenity')):
            command = bwenv.password_dialog_command('Master password:')
        self.assertEqual(command[0], '/usr/bin/zenity')
        self.assertIn('--hide-text', command)

    @patch.dict(os.environ, {'XDG_CURRENT_DESKTOP': 'KDE'}, clear=True)
    def test_no_display_means_no_dialog(self):
        with patch.object(bwenv, 'IS_WINDOWS', False), patch.object(bwenv.sys, 'platform', 'linux'), \
                patch('shutil.which', self._which('kdialog', 'zenity')):
            self.assertIsNone(bwenv.password_dialog_command('Master password:'))

    def test_dialog_output_keeps_spaces_but_not_the_newline(self):
        with patch.object(bwenv, 'password_dialog_command', return_value=['dialog']), \
                patch('subprocess.run', return_value=Mock(returncode=0, stdout='﻿ pass word \n')):
            self.assertEqual(bwenv.ask_password_in_dialog('Master password:'), ' pass word ')

    def test_cancelled_dialog_returns_none(self):
        with patch.object(bwenv, 'password_dialog_command', return_value=['dialog']), \
                patch('subprocess.run', return_value=Mock(returncode=1, stdout='')):
            self.assertIsNone(bwenv.ask_password_in_dialog('Master password:'))

    def test_no_dialog_tool_falls_back_to_tkinter_or_reports_none_available(self):
        with patch.object(bwenv, 'password_dialog_command', return_value=None), \
                patch.dict(sys.modules, {'tkinter': None}):
            with self.assertRaises(bwenv.NoPasswordDialog):
                bwenv.ask_password_in_dialog('Master password:')


class TestDialogUnlock(unittest.TestCase):
    """Unlocking a locked vault through the dialog when there is no terminal"""

    PASSWORD = 'correct horse battery staple'

    def setUp(self):
        self.responses = {('bw', 'status'): '{"status":"locked"}'}
        self.passwords_tried = []

        def run(command, **kwargs):
            if command[:3] == ['bw', 'unlock', '--passwordenv']:
                password = kwargs['env'][command[3]]
                self.passwords_tried.append(password)
                if password == self.PASSWORD:
                    return Mock(returncode=0, stdout='dialog_session_token\n', stderr='')
                return Mock(returncode=1, stdout='', stderr='Invalid master password.')
            return fake_bw(self.responses)(command, **kwargs)

        for target, value in (('subprocess.run', Mock(side_effect=run)), ('sys.stdin', Mock())):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        sys.stdin.isatty.return_value = False
        env_patcher = patch.dict(os.environ, {}, clear=False)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop('BW_SESSION', None)
        os.environ.pop('BWENV_PROMPT', None)

    def _dialog(self, *answers):
        patcher = patch.object(bwenv, 'ask_password_in_dialog', side_effect=list(answers))
        self.addCleanup(patcher.stop)
        return patcher.start()

    def test_no_terminal_unlocks_through_the_dialog(self):
        """The password goes to bw via an environment variable, never argv or the logs"""
        self._dialog(self.PASSWORD)
        client = bwenv.BitwardenClient(no_sync=True)

        with self.assertLogs(level='DEBUG') as logs:
            logging.getLogger().debug("unlock test start")
            client._run_bw_command(['list', 'items'])

        unlock = [c for c in subprocess.run.call_args_list if c[0][0][:2] == ['bw', 'unlock']]
        self.assertEqual(len(unlock), 1)
        self.assertNotIn(self.PASSWORD, ' '.join(unlock[0][0][0]))
        self.assertEqual(client._session, 'dialog_session_token')
        self.assertNotIn(self.PASSWORD, '\n'.join(logs.output))
        self.assertNotIn(bwenv.MASTER_PASSWORD_ENV, os.environ)

    def test_wrong_password_asks_again(self):
        dialog = self._dialog('wrong', self.PASSWORD)

        bwenv.BitwardenClient(no_sync=True)._run_bw_command(['list', 'items'])

        self.assertEqual(self.passwords_tried, ['wrong', self.PASSWORD])
        self.assertIn('incorrect', dialog.call_args_list[1][0][0].lower())

    def test_three_wrong_passwords_give_up(self):
        self._dialog('a', 'b', 'c', self.PASSWORD)

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient(no_sync=True)._run_bw_command(['list', 'items'])

        self.assertEqual(len(self.passwords_tried), 3)
        self.assertIn('3 attempts', str(cm.exception))

    def test_other_unlock_errors_are_not_retried(self):
        """Only a wrong password is worth asking again for; anything else is reported at once"""
        self._dialog('anything', self.PASSWORD)
        with patch.object(bwenv.BitwardenClient, '_exec_bw', autospec=True) as mock_exec:
            mock_exec.side_effect = lambda self_, args, input_text=None, interactive=False, extra_env=None: (
                Mock(returncode=0, stdout='{"status":"locked"}', stderr='') if args == ['status']
                else Mock(returncode=1, stdout='', stderr='Failed to connect to the server.'))
            with self.assertRaises(bwenv.BWEnvError) as cm:
                bwenv.BitwardenClient(no_sync=True)._run_bw_command(['list', 'items'])

        self.assertIn('Failed to connect', str(cm.exception))

    def test_cancel_stops(self):
        self._dialog(None)

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient(no_sync=True)._run_bw_command(['list', 'items'])

        self.assertIn('cancelled', str(cm.exception).lower())
        self.assertEqual(self.passwords_tried, [])

    def test_no_dialog_available_explains_how_to_unlock(self):
        self._dialog(bwenv.NoPasswordDialog())

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient(no_sync=True)._run_bw_command(['list', 'items'])

        self.assertIn('BW_SESSION', str(cm.exception))

    def test_bwenv_prompt_gui_uses_the_dialog_even_on_a_terminal(self):
        sys.stdin.isatty.return_value = True
        os.environ['BWENV_PROMPT'] = 'gui'
        self._dialog(self.PASSWORD)

        bwenv.BitwardenClient(no_sync=True)._run_bw_command(['list', 'items'])

        self.assertEqual(self.passwords_tried, [self.PASSWORD])

    def test_bwenv_prompt_none_never_asks(self):
        os.environ['BWENV_PROMPT'] = 'none'
        dialog = self._dialog(self.PASSWORD)

        with self.assertRaises(bwenv.BWEnvError):
            bwenv.BitwardenClient(no_sync=True)._run_bw_command(['list', 'items'])

        dialog.assert_not_called()

    def test_invalid_bwenv_prompt_is_an_error(self):
        os.environ['BWENV_PROMPT'] = 'popup'

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient(no_sync=True)._run_bw_command(['list', 'items'])

        self.assertIn('BWENV_PROMPT', str(cm.exception))


class TestOpUriMatching(unittest.TestCase):
    """op:// references must name exactly one item"""

    @staticmethod
    def _item(item_id, uri, password):
        return {"id": item_id, "name": item_id, "organizationId": None,
                "login": {"password": password, "uris": [{"uri": uri}]}, "fields": []}

    def _client(self, items):
        patcher = patch('subprocess.run', side_effect=fake_bw({('bw', 'list', 'items'): json.dumps(items)}))
        patcher.start()
        self.addCleanup(patcher.stop)
        env_patcher = patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        return bwenv.BitwardenClient(no_sync=True)

    def test_item_name_prefix_does_not_match(self):
        """op://Prod/db must not resolve to the item op://Prod/db-prod, even if that is listed first"""
        client = self._client([self._item('db-prod', 'op://Prod/db-prod', 'WRONG'),
                               self._item('db', 'op://Prod/db', 'RIGHT')])

        self.assertEqual(client.find_item_by_uri_prefix('Prod', 'db')['id'], 'db')

    def test_only_a_prefix_match_is_not_found(self):
        """With only op://Prod/db-prod present, op://Prod/db is not found"""
        client = self._client([self._item('db-prod', 'op://Prod/db-prod', 'WRONG')])

        self.assertIsNone(client.find_item_by_uri_prefix('Prod', 'db'))

    def test_two_items_with_the_same_reference_is_an_error(self):
        """Another item (e.g. shared into an org collection) cannot silently shadow yours"""
        client = self._client([self._item('mine', 'op://Prod/db', 'MINE'),
                               self._item('theirs', 'op://Prod/db', 'THEIRS')])

        with self.assertRaises(bwenv.BWEnvError) as cm:
            client.find_item_by_uri_prefix('Prod', 'db')
        self.assertIn('op://Prod/db', str(cm.exception))

    def test_same_item_listing_the_reference_twice_is_fine(self):
        """One item carrying the URI twice is still one item"""
        item = self._item('db', 'op://Prod/db', 'RIGHT')
        item['login']['uris'].append({"uri": "op://Prod/db"})
        client = self._client([item])

        self.assertEqual(client.find_item_by_uri_prefix('Prod', 'db')['id'], 'db')


class TestOrganizationResolution(unittest.TestCase):
    """Organization lookups report real errors instead of 'No item found'"""

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_failed_organization_list_is_reported(self, mock_run):
        mock_run.side_effect = fake_bw({('bw', 'list', 'organizations'): (1, '', 'Vault is locked.')})

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient(no_sync=True)._resolve_organization('MyOrg')
        self.assertIn('Vault is locked', str(cm.exception))

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_unknown_organization_is_reported(self, mock_run):
        mock_run.side_effect = fake_bw({('bw', 'list', 'organizations'): '[{"id": "o1", "name": "Other"}]'})

        with self.assertRaises(bwenv.BWEnvError) as cm:
            bwenv.BitwardenClient(no_sync=True)._resolve_organization('MyOrg')
        self.assertIn("'MyOrg'", str(cm.exception))


class TestEnvironmentProcessor(unittest.TestCase):
    """Test cases for environment variable processing"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_client = Mock(spec=bwenv.BitwardenClient)
        self.processor = bwenv.EnvironmentProcessor(self.mock_client)
    
    @patch.dict(os.environ, {
        'NORMAL_VAR': 'normal_value',
        'OP_VAR1': 'op://Employee/example/secret',
        'OP_VAR2': 'op://My Vault/My Item/api_key',
        'BW_VAR1': 'bw://myvault/Demo/Data/DEMO_DATA/username',
        'BW_VAR2': 'bw://someorg/Demo/Data/DEMO_DATA/password',
        'ANOTHER_NORMAL': 'another_value'
    }, clear=True)
    def test_scan_environment(self):
        """Test scanning environment for op:// and bw:// URIs"""
        uri_vars = self.processor.scan_environment()
        
        expected = {
            'OP_VAR1': 'op://Employee/example/secret',
            'OP_VAR2': 'op://My Vault/My Item/api_key',
            'BW_VAR1': 'bw://myvault/Demo/Data/DEMO_DATA/username',
            'BW_VAR2': 'bw://someorg/Demo/Data/DEMO_DATA/password'
        }
        self.assertEqual(uri_vars, expected)
    
    def test_resolve_uri_success(self):
        """Test successful URI resolution"""
        # Mock the client methods
        mock_item = {
            'fields': [{'name': 'secret', 'value': 'resolved_value'}]
        }
        self.mock_client.find_item_by_uri_prefix.return_value = mock_item
        self.mock_client.get_field_value.return_value = 'resolved_value'
        
        result = self.processor.resolve_uri('op://Employee/example/secret')
        
        self.assertEqual(result, 'resolved_value')
        self.mock_client.find_item_by_uri_prefix.assert_called_once_with('Employee', 'example')
        self.mock_client.get_field_value.assert_called_once_with(mock_item, 'secret')
    
    def test_resolve_uri_invalid_format(self):
        """Test URI resolution with invalid format"""
        with self.assertRaises(bwenv.BWEnvError) as cm:
            self.processor.resolve_uri('invalid-uri')
        
        self.assertIn("Invalid URI format", str(cm.exception))
    
    def test_resolve_uri_item_not_found(self):
        """Test URI resolution when item is not found"""
        self.mock_client.find_item_by_uri_prefix.return_value = None
        
        with self.assertRaises(bwenv.BWEnvError) as cm:
            self.processor.resolve_uri('op://Employee/example/secret')
        
        self.assertIn("No Bitwarden item found", str(cm.exception))
    
    def test_resolve_uri_field_not_found(self):
        """Test URI resolution when field is not found"""
        mock_item = {'fields': []}
        self.mock_client.find_item_by_uri_prefix.return_value = mock_item
        self.mock_client.get_field_value.return_value = None
        
        with self.assertRaises(bwenv.BWEnvError) as cm:
            self.processor.resolve_uri('op://Employee/example/secret')
        
        self.assertIn("Field 'secret' not found", str(cm.exception))
    
    def test_resolve_bw_uri_success(self):
        """Test successful bw:// URI resolution"""
        # Mock the resolve_bw_uri_to_value method
        self.mock_client.resolve_bw_uri_to_value.return_value = 'resolved_bw_value'
        
        result = self.processor.resolve_uri('bw://myvault/Demo/Data/DEMO_DATA/username')
        
        self.assertEqual(result, 'resolved_bw_value')
        self.mock_client.resolve_bw_uri_to_value.assert_called_once_with('bw://myvault/Demo/Data/DEMO_DATA/username')
    
    def test_resolve_bw_uri_item_not_found(self):
        """Test bw:// URI resolution when item is not found"""
        self.mock_client.resolve_bw_uri_to_value.side_effect = ValueError("No item found")
        
        with self.assertRaises(bwenv.BWEnvError) as cm:
            self.processor.resolve_uri('bw://myvault/Demo/Data/DEMO_DATA/username')
        
        self.assertIn("Failed to resolve bw:// URI", str(cm.exception))
    
    
    @patch.dict(os.environ, {
        'NORMAL_VAR': 'normal_value',
        'OP_VAR': 'op://Employee/example/secret'
    }, clear=True)
    def test_create_resolved_environment(self):
        """Test creating resolved environment"""
        # Mock the resolution
        self.mock_client.find_item_by_uri_prefix.return_value = {'fields': []}
        self.mock_client.get_field_value.return_value = 'resolved_secret'
        
        resolved_env = self.processor.create_resolved_environment()
        
        expected_env = {
            'NORMAL_VAR': 'normal_value',
            'OP_VAR': 'resolved_secret'
        }
        self.assertEqual(resolved_env, expected_env)


class TestIntegration(unittest.TestCase):
    """Integration tests for bwenv functionality"""
    
    @patch('subprocess.run')
    def test_bw_cli_not_available(self, mock_run):
        """Test behavior when Bitwarden CLI is not available"""
        mock_run.side_effect = FileNotFoundError()
        
        client = bwenv.BitwardenClient()
        
        with self.assertRaises(bwenv.BWEnvError) as cm:
            client.get_items_with_op_uris()
        
        self.assertIn("not found", str(cm.exception))
    
    @patch('subprocess.run')
    def test_bw_cli_authentication_error(self, mock_run):
        """Test behavior when Bitwarden CLI authentication fails"""
        mock_run.return_value = Mock(stdout='', stderr="You are not logged in", returncode=1)
        
        client = bwenv.BitwardenClient()
        
        with self.assertRaises(bwenv.BWEnvError) as cm:
            client.get_items_with_op_uris()
        
        self.assertIn("You are not logged in", str(cm.exception))


class TestArgumentParsing(unittest.TestCase):
    """Test cases for the new '--' separator argument parsing functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock sys.argv to test parse_args_with_separator
        self.original_argv = sys.argv.copy()
    
    def tearDown(self):
        """Clean up after tests"""
        sys.argv = self.original_argv
    
    def test_parse_args_no_separator_original_behavior(self):
        """Test original behavior without '--' separator"""
        sys.argv = ['bwenv.py', 'run', '--debug', 'echo', 'hello']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'run')
        self.assertTrue(args.debug)
        self.assertEqual(args.cmd_args, ['echo', 'hello'])
    
    def test_parse_args_with_separator_basic(self):
        """Test basic '--' separator functionality"""
        sys.argv = ['bwenv.py', 'run', '--', 'echo', 'hello']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'run')
        self.assertEqual(args.cmd_args, ['echo', 'hello'])
    
    def test_parse_args_with_separator_and_flags_before(self):
        """Test '--' separator with bwenv flags before"""
        sys.argv = ['bwenv.py', 'run', '--debug', '--no-sync', '--', 'echo', 'hello']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'run')
        self.assertTrue(args.debug)
        self.assertTrue(args.no_sync)
        self.assertEqual(args.cmd_args, ['echo', 'hello'])
    
    def test_parse_args_with_separator_and_flags_after(self):
        """Test '--' separator with command flags after"""
        sys.argv = ['bwenv.py', 'run', '--', 'echo', 'hello', '--debug']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'run')
        self.assertEqual(args.cmd_args, ['echo', 'hello', '--debug'])
    
    def test_parse_args_with_separator_flags_separated(self):
        """Test '--' separator properly separating bwenv and command flags"""
        sys.argv = ['bwenv.py', 'run', '--no-sync', '--', 'echo', '--debug', 'hello']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'run')
        self.assertTrue(args.no_sync)
        self.assertFalse(args.debug)  # --debug is after --, so not for bwenv
        self.assertEqual(args.cmd_args, ['echo', '--debug', 'hello'])
    
    def test_parse_args_with_separator_subcommand_flags(self):
        """Test '--' separator with subcommand-level flags"""
        sys.argv = ['bwenv.py', 'run', '--debug', '--', 'echo', 'hello']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'run')
        self.assertTrue(args.debug)
        self.assertEqual(args.cmd_args, ['echo', 'hello'])
    
    def test_parse_args_read_command_unaffected(self):
        """Test that read command is unaffected by separator logic"""
        sys.argv = ['bwenv.py', 'read', '--debug', 'op://vault/item/field']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'read')
        self.assertTrue(args.debug)
        self.assertEqual(args.uri, 'op://vault/item/field')
    
    def test_parse_args_separator_not_after_run(self):
        """Test that '--' not after 'run' is ignored"""
        # This case should be treated as an error since -- comes before run
        sys.argv = ['bwenv.py', '--', '--debug', 'run', 'echo', 'hello']
        with self.assertRaises(SystemExit):
            bwenv.parse_args_with_separator()
    
    def test_parse_args_multiple_separators(self):
        """Test behavior with multiple '--' separators (only first one counts)"""
        sys.argv = ['bwenv.py', 'run', '--', 'echo', '--', 'hello']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'run')
        self.assertEqual(args.cmd_args, ['echo', '--', 'hello'])
    
    def test_parse_args_empty_command_after_separator(self):
        """Test '--' separator with empty command"""
        sys.argv = ['bwenv.py', 'run', '--']
        args = bwenv.parse_args_with_separator()
        
        self.assertEqual(args.command, 'run')
        self.assertEqual(args.cmd_args, [])

    def _parse(self, *argv):
        sys.argv = ['bwenv.py', *argv]
        return bwenv.parse_args_with_separator()

    def test_child_command_may_contain_run(self):
        """`run -- npm run build` (or docker/cargo/kubectl run) runs that command"""
        args = self._parse('run', '--', 'npm', 'run', 'build')
        self.assertEqual((args.command, args.cmd_args), ('run', ['npm', 'run', 'build']))

        args = self._parse('--debug', 'run', '--', 'docker', 'run', 'alpine')
        self.assertTrue(args.debug)
        self.assertEqual(args.cmd_args, ['docker', 'run', 'alpine'])

    def test_child_command_may_contain_read_or_send(self):
        """Without `--`, words after the child command are its arguments, not bwenv subcommands"""
        self.assertEqual(self._parse('run', 'echo', 'read').cmd_args, ['echo', 'read'])
        self.assertEqual(self._parse('run', 'make', 'send').cmd_args, ['make', 'send'])

    def test_flags_after_child_command_belong_to_it(self):
        """`run grep --debug f` passes --debug to grep and leaves bwenv's debug mode off"""
        args = self._parse('run', 'grep', '--debug', 'f')
        self.assertFalse(args.debug)
        self.assertEqual(args.cmd_args, ['grep', '--debug', 'f'])

    def test_only_first_separator_counts(self):
        """With two `--`, everything after the first goes to the child unchanged"""
        args = self._parse('run', '--', 'tool', '--debug', '--', 'file')
        self.assertFalse(args.debug)
        self.assertEqual(args.cmd_args, ['tool', '--debug', '--', 'file'])

    def test_read_and_send_flags_anywhere(self):
        """read and send run no child, so bwenv flags may follow the URI"""
        args = self._parse('read', 'op://vault/item/field', '--debug')
        self.assertTrue(args.debug)
        self.assertEqual(args.uri, 'op://vault/item/field')

        args = self._parse('send', '--no-sync', '--name', 'X', 'op://v/i/f', '--max-access', '3')
        self.assertTrue(args.no_sync)
        self.assertEqual((args.name, args.uri, args.max_access), ('X', ['op://v/i/f'], 3))


class TestRunCommand(unittest.TestCase):
    """`run` hands over to the child so signals and exit codes are the child's own"""

    def _args(self, *cmd):
        return argparse.Namespace(cmd_args=list(cmd), no_sync=True, debug=False)

    @patch.dict(os.environ, {'BW_SESSION': 'session', 'PLAIN': 'value'}, clear=True)
    def test_posix_replaces_bwenv_with_the_child(self):
        """On POSIX, bwenv execs the child: Ctrl-C, SIGTERM and the exit status go straight to it"""
        with patch.object(bwenv, 'IS_WINDOWS', False), patch('os.execvpe') as mock_exec:
            mock_exec.side_effect = SystemExit(0)  # exec never returns
            with self.assertRaises(SystemExit):
                bwenv.run_command(self._args('npm', 'start'))

        command, argv, env = mock_exec.call_args[0]
        self.assertEqual((command, argv), ('npm', ['npm', 'start']))
        self.assertEqual(env, {'PLAIN': 'value'})

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_command_exits_127(self):
        """A command that does not exist exits 127, like a shell, without a traceback"""
        with patch.object(bwenv, 'IS_WINDOWS', False), \
                patch('os.execvpe', side_effect=FileNotFoundError(2, 'No such file')), \
                patch('sys.stderr'), self.assertRaises(SystemExit) as cm:
            bwenv.run_command(self._args('no-such-command'))

        self.assertEqual(cm.exception.code, 127)

    @patch.dict(os.environ, {}, clear=True)
    def test_windows_waits_through_ctrl_c_and_passes_exit_code(self):
        """On Windows (no real exec), Ctrl-C does not kill the child; its exit code is bwenv's"""
        process = Mock()
        process.wait.side_effect = [KeyboardInterrupt(), 3]
        with patch.object(bwenv, 'IS_WINDOWS', True), \
                patch('shutil.which', return_value='C:\\nodejs\\npm.cmd'), \
                patch('subprocess.Popen', return_value=process) as mock_popen, \
                self.assertRaises(SystemExit) as cm:
            bwenv.run_command(self._args('npm', 'start'))

        self.assertEqual(cm.exception.code, 3)
        self.assertEqual(mock_popen.call_args[0][0], ['C:\\nodejs\\npm.cmd', 'start'])
        self.assertEqual(process.wait.call_count, 2)

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_read_prints_utf8_whatever_the_console_encoding(self, mock_run):
        """A secret outside the console code page (e.g. cp1252 on Windows) still prints, as UTF-8"""
        items = [{"id": "i1", "name": "svc", "organizationId": None, "fields": [],
                  "login": {"password": "Ā-π-€", "uris": [{"uri": "op://Prod/svc"}]}}]
        mock_run.side_effect = fake_bw({('bw', 'list', 'items'): json.dumps(items)})
        buffer = io.BytesIO()
        stdout = io.TextIOWrapper(buffer, encoding='cp1252')

        with patch('sys.stdout', stdout):
            bwenv.read_secret(argparse.Namespace(uri='op://Prod/svc/password', no_sync=True))
            stdout.flush()

        self.assertEqual(buffer.getvalue().decode('utf-8').strip(), 'Ā-π-€')


class TestFunctional(unittest.TestCase):
    """Functional tests: run bwenv.py as a real process, on any OS"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_script = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bwenv.py')]
        # The real environment (Windows needs SYSTEMROOT, everything needs PATH), minus anything bwenv would resolve
        self.env = {key: value for key, value in os.environ.items()
                    if not bwenv.URIParser.is_supported_uri(value) and key not in bwenv.BW_CREDENTIAL_VARS}
        self.env['TEST_VAR'] = 'normal_value'

    def _child(self, code):
        """A portable child command: the running Python executing `code`"""
        return [sys.executable, '-c', code]

    def _run(self, *argv):
        return subprocess.run(self.test_script + list(argv), capture_output=True, text=True, env=self.env)

    def test_script_help(self):
        """Test that the script shows help correctly"""
        result = self._run('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn("Bitwarden Environment Variable Processor", result.stdout)
        self.assertIn("run", result.stdout)
        self.assertIn("read", result.stdout)

    def test_script_no_args(self):
        """Test script behavior with no arguments"""
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("usage:", result.stdout)

    def test_run_command_no_command(self):
        """Test run subcommand with no command specified"""
        result = self._run('run')
        self.assertEqual(result.returncode, 1)
        self.assertIn("No command specified", result.stderr)

    def test_run_command_no_op_vars(self):
        """With no references to resolve, the command runs without touching Bitwarden"""
        result = self._run('run', *self._child("print('test')"))
        self.assertEqual(result.returncode, 0)
        self.assertIn('test', result.stdout)

    def test_run_command_with_separator_no_op_vars(self):
        """Test running command with '--' separator when no op:// variables are present"""
        result = self._run('run', '--', *self._child("print('test')"))
        self.assertEqual(result.returncode, 0)
        self.assertIn('test', result.stdout)

    def test_separator_flag_isolation(self):
        """Test that flags are properly isolated by '--' separator"""
        result = self._run('--no-sync', 'run', '--', *self._child("import sys; print(sys.argv[1:])"), '--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('--help', result.stdout)
        self.assertNotIn('usage:', result.stdout)

    def test_backward_compatibility(self):
        """Test that existing usage patterns still work"""
        result = self._run('--no-sync', 'run', *self._child("print('backward_compat')"))
        self.assertEqual(result.returncode, 0)
        self.assertIn('backward_compat', result.stdout)

        result = self._run('run', '--no-sync', *self._child("print('subcommand_flags')"))
        self.assertEqual(result.returncode, 0)
        self.assertIn('subcommand_flags', result.stdout)

    def test_exit_code_is_the_childs(self):
        """bwenv run exits with the command's own exit code"""
        result = self._run('run', '--', *self._child("import sys; sys.exit(3)"))
        self.assertEqual(result.returncode, 3)

    def test_child_does_not_receive_bw_session(self):
        """The command bwenv runs does not inherit BW_SESSION"""
        self.env['BW_SESSION'] = 'not-for-the-child'
        result = self._run('run', '--', *self._child("import os; print(os.environ.get('BW_SESSION', '<unset>'))"))
        self.assertEqual(result.stdout.strip(), '<unset>')

    def test_missing_command_exits_127(self):
        """A command that does not exist exits 127"""
        result = self._run('run', '--', 'no-such-command-for-bwenv-tests')
        self.assertEqual(result.returncode, 127)
        self.assertIn('not found', result.stderr)


class TestSendCommand(unittest.TestCase):
    """End-to-end tests of `bwenv send`, with only the bw CLI mocked"""

    SECRET = 'S3cr3t-Value-Do-Not-Log'
    ITEMS = [
        {"id": "i1", "name": "svc", "organizationId": None, "folderId": None,
         "login": {"username": "svc-user", "password": SECRET, "uris": [{"uri": "op://Prod/svc"}]},
         "fields": [{"name": "api_key", "value": "key-123"}]},
        {"id": "i2", "name": "dup", "organizationId": None, "folderId": "f1",
         "login": {"password": "a"}, "fields": []},
        {"id": "i3", "name": "dup", "organizationId": None, "folderId": "f2",
         "login": {"password": "b"}, "fields": []},
    ]

    def setUp(self):
        self.responses = {
            ('bw', 'list', 'items'): json.dumps(self.ITEMS),
            ('bw', 'send', 'create'): json.dumps({"accessUrl": "https://vault.example/#/send/abc"}),
        }
        patcher = patch('subprocess.run', side_effect=lambda command, **kwargs: fake_bw(self.responses)(command, **kwargs))
        self.mock_run = patcher.start()
        self.addCleanup(patcher.stop)
        env_patcher = patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

    def _send(self, *uris, **options):
        args = argparse.Namespace(uri=list(uris), no_sync=True, name=options.get('name'),
                    max_access=options.get('max_access', 1), expire_hours=options.get('expire_hours', 24.0))
        with patch('builtins.print') as mock_print, self.assertLogs(level='DEBUG') as logs:
            logging.getLogger().debug("send test start")
            bwenv.send_item(args)
        return [c[0][0] for c in mock_print.call_args_list], '\n'.join(logs.output)

    def _created_sends(self):
        sends = []
        for call in self.mock_run.call_args_list:
            if call[0][0][1:3] == ['send', 'create']:
                self.assertEqual(call[0][0], ['bw', 'send', 'create'], "payload must not be on the command line")
                sends.append(json.loads(base64.b64decode(call[1]['input'])))
        return sends

    def test_field_send_goes_through_stdin_with_safe_defaults(self):
        """The secret reaches bw on stdin only, and the Send is single-use, hidden and anonymous"""
        printed, logs = self._send('op://Prod/svc/password')

        self.assertEqual(printed, ["https://vault.example/#/send/abc"])
        [send] = self._created_sends()
        self.assertEqual(send['text']['text'], self.SECRET)
        self.assertTrue(send['text']['hidden'])
        self.assertTrue(send['hideEmail'])
        self.assertEqual(send['maxAccessCount'], 1)
        self.assertEqual(send['name'], 'Shared secret')
        self.assertNotIn(['bw', 'encode'], [c[0][0] for c in self.mock_run.call_args_list])
        self.assertNotIn(self.SECRET, logs)
        self.assertNotIn(base64.b64encode(self.SECRET.encode()).decode()[:16], logs)

    def test_item_send_for_op_uri_without_field(self):
        """op://vault/item sends the whole item as JSON"""
        self._send('op://Prod/svc')

        [send] = self._created_sends()
        self.assertEqual(json.loads(send['text']['text']),
                         {"username": "svc-user", "password": self.SECRET, "api_key": "key-123"})

    def test_item_send_for_bw_uri_without_field(self):
        """bw://vault/item sends the whole item as JSON"""
        self._send('bw://myvault/svc')

        [send] = self._created_sends()
        self.assertEqual(json.loads(send['text']['text'])['api_key'], 'key-123')

    def test_options_loosen_the_defaults(self):
        """--max-access 0 means unlimited, --expire-hours sets the deletion date, --name the title"""
        before = datetime.datetime.now(datetime.timezone.utc)
        self._send('op://Prod/svc/password', name='For Sam', max_access=0, expire_hours=2)

        [send] = self._created_sends()
        self.assertIsNone(send['maxAccessCount'])
        self.assertEqual(send['name'], 'For Sam')
        deletion = datetime.datetime.strptime(send['deletionDate'], '%Y-%m-%dT%H:%M:%S.%fZ').replace(
            tzinfo=datetime.timezone.utc)
        self.assertAlmostEqual((deletion - before).total_seconds(), 7200, delta=60)

    def test_several_uris_are_numbered_not_named_after_the_uri(self):
        """The Send name never reveals the reference"""
        printed, _ = self._send('op://Prod/svc/password', 'op://Prod/svc/api_key', name='Creds')

        self.assertEqual([s['name'] for s in self._created_sends()], ['Creds (1 of 2)', 'Creds (2 of 2)'])
        self.assertEqual(len(printed), 2)

    def test_ambiguous_uri_exits_cleanly(self):
        """An ambiguous name is a clean error (exit 1), not a traceback, and creates no Send"""
        with self.assertRaises(SystemExit) as cm:
            self._send('bw://myvault/dup/password')

        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(self._created_sends(), [])

    def test_missing_access_url_is_an_error_and_not_echoed(self):
        """If bw returns no access URL, bwenv reports it without printing bw's output (it holds the secret)"""
        self.responses[('bw', 'send', 'create')] = json.dumps({"text": {"text": self.SECRET}})

        with patch('sys.stderr') as mock_stderr, self.assertRaises(SystemExit):
            self._send('op://Prod/svc/password')

        written = ''.join(str(c[0][0]) for c in mock_stderr.write.call_args_list)
        self.assertNotIn(self.SECRET, written)


class TestSecretHandling(unittest.TestCase):
    """Secrets never reach logs, and the child of `run` gets no Bitwarden credentials"""

    SECRET = 'S3cr3t-Value-Do-Not-Log'
    ITEMS = [{"id": "i1", "name": "svc", "organizationId": None, "folderId": None,
              "login": {"password": SECRET, "uris": [{"uri": "op://Prod/svc"}]}, "fields": []}]

    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_debug_logs_never_contain_secret_values(self, mock_run):
        """--debug logs lengths only, for op://, bw:// and read"""
        mock_run.side_effect = fake_bw({('bw', 'list', 'items'): json.dumps(self.ITEMS)})
        processor = bwenv.EnvironmentProcessor(bwenv.BitwardenClient(no_sync=True))

        with self.assertLogs(level='DEBUG') as logs, patch('builtins.print'):
            self.assertEqual(processor.resolve_uri('op://Prod/svc/password'), self.SECRET)
            self.assertEqual(processor.resolve_uri('bw://myvault/svc/password'), self.SECRET)
            bwenv.read_secret(Mock(uri='op://Prod/svc/password', no_sync=True))

        self.assertNotIn(self.SECRET[:8], '\n'.join(logs.output))

    @patch.dict(os.environ, {'BW_SESSION': 'session', 'BW_PASSWORD': 'pw', 'BW_CLIENTID': 'id',
                             'BW_CLIENTSECRET': 'secret', 'KEEP_ME': 'yes'}, clear=True)
    def test_run_child_gets_no_bitwarden_credentials(self):
        """The command bwenv runs cannot use our session to read the rest of the vault"""
        processor = bwenv.EnvironmentProcessor(Mock())

        env = processor.create_resolved_environment()

        self.assertEqual(env, {'KEEP_ME': 'yes'})


class TestSendCommandIntegration(unittest.TestCase):
    """Integration tests for send command"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_script = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bwenv.py')]
    
    def test_send_command_help(self):
        """Test send command help"""
        result = subprocess.run(self.test_script + ['send', '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("URI(s) to send", result.stdout)
        self.assertIn("--name", result.stdout)
    
    def test_send_command_no_uri(self):
        """Test send command without URI"""
        result = subprocess.run(self.test_script + ['send'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("required", result.stderr)


class MemorySessionCache(bwenv.SessionCache):
    """A session cache that only lives in this test"""
    name = 'test cache'

    def __init__(self, session=None, fail_store=False):
        self.session = session
        self.stored = []
        self.cleared = 0
        self.loads = 0
        self.fail_store = fail_store

    def load(self):
        self.loads += 1
        return self.session

    def store(self, session, seconds):
        if self.fail_store:
            raise bwenv.BWEnvError("store is broken")
        self.session = session
        self.stored.append((session, seconds))

    def clear(self):
        self.session = None
        self.cleared += 1


class TestSessionCacheSetting(unittest.TestCase):
    """BWENV_SESSION_CACHE: how long to keep the session"""

    def _seconds(self, value):
        with patch.dict(os.environ, {'BWENV_SESSION_CACHE': value}):
            return bwenv.session_cache_seconds()

    def test_durations(self):
        for value, seconds in (('', 0), ('0', 0), ('3600', 3600), ('90s', 90), ('30m', 1800),
                               ('8h', 28800), ('1.5h', 5400), ('2d', 172800), (' 8H ', 28800)):
            self.assertEqual(self._seconds(value), seconds, value)

    def test_unset_means_no_cache(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('BWENV_SESSION_CACHE', None)
            self.assertEqual(bwenv.session_cache_seconds(), 0)

    def test_nonsense_is_an_error(self):
        for value in ('soon', '8 hours', '-1h', 'h'):
            with self.assertRaises(bwenv.BWEnvError, msg=value):
                self._seconds(value)


class TestSessionCacheUse(unittest.TestCase):
    """The client uses, refreshes and discards the cached session"""

    UNLOCKED_BY = 'fresh_session'

    def setUp(self):
        self.valid_sessions = {self.UNLOCKED_BY}

        def run(command, **kwargs):
            if command == ['bw', 'status']:
                unlocked = kwargs['env'].get('BW_SESSION') in self.valid_sessions
                return Mock(returncode=0, stdout=json.dumps({"status": "unlocked" if unlocked else "locked"}), stderr='')
            if command[:2] == ['bw', 'unlock']:
                return Mock(returncode=0, stdout=self.UNLOCKED_BY + '\n', stderr='')
            return Mock(returncode=0, stdout='[]', stderr='')

        patcher = patch('subprocess.run', side_effect=run)
        self.mock_run = patcher.start()
        self.addCleanup(patcher.stop)
        env_patcher = patch.dict(os.environ, {'BWENV_SESSION_CACHE': '8h', 'BWENV_PROMPT': 'gui'})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop('BW_SESSION', None)
        dialog = patch.object(bwenv, 'ask_password_in_dialog', return_value='master password')
        self.dialog = dialog.start()
        self.addCleanup(dialog.stop)

    def _list_items(self, cache):
        client = bwenv.BitwardenClient(no_sync=True, session_cache=cache)
        client._run_bw_command(['list', 'items'])
        return client

    def _session_given_to(self, subcommand):
        return [c[1]['env'].get('BW_SESSION') for c in self.mock_run.call_args_list if c[0][0][1] == subcommand]

    def test_an_unlock_is_cached_with_its_lifetime(self):
        cache = MemorySessionCache()
        self._list_items(cache)
        self.assertEqual(cache.stored, [(self.UNLOCKED_BY, 28800)])
        self.dialog.assert_called_once()

    def test_a_cached_session_saves_the_password_prompt(self):
        self.valid_sessions.add('cached_session')
        cache = MemorySessionCache('cached_session')
        client = self._list_items(cache)
        self.dialog.assert_not_called()
        self.assertEqual(client._session, 'cached_session')
        self.assertEqual(self._session_given_to('list'), ['cached_session'])
        self.assertEqual(cache.stored, [])
        self.assertNotIn('BW_SESSION', os.environ)

    def test_a_cached_session_that_no_longer_unlocks_is_discarded(self):
        cache = MemorySessionCache('stale_session')
        client = self._list_items(cache)
        self.assertEqual(cache.cleared, 1)
        self.dialog.assert_called_once()
        self.assertEqual(client._session, self.UNLOCKED_BY)
        self.assertEqual(cache.stored, [(self.UNLOCKED_BY, 28800)])

    def test_an_inherited_session_wins(self):
        self.valid_sessions.add('inherited')
        cache = MemorySessionCache('cached_session')
        with patch.dict(os.environ, {'BW_SESSION': 'inherited'}):
            self._list_items(cache)
        self.assertEqual(cache.loads, 0)
        self.assertEqual(self._session_given_to('list'), ['inherited'])

    def test_no_setting_means_no_cache(self):
        os.environ.pop('BWENV_SESSION_CACHE')
        self.valid_sessions.add('cached_session')
        cache = MemorySessionCache('cached_session')
        self._list_items(cache)
        self.assertEqual((cache.loads, cache.stored), (0, []))
        self.dialog.assert_called_once()

    def test_a_cache_that_cannot_store_only_warns(self):
        cache = MemorySessionCache(fail_store=True)
        with patch('sys.stderr', new_callable=io.StringIO) as stderr:
            client = self._list_items(cache)
        self.assertIn('could not cache', stderr.getvalue())
        self.assertNotIn(self.UNLOCKED_BY, stderr.getvalue())
        self.assertEqual(client._session, self.UNLOCKED_BY)

    def test_no_session_store_warns_and_carries_on(self):
        with patch.object(bwenv, 'default_session_cache', return_value=None), \
                patch('sys.stderr', new_callable=io.StringIO) as stderr:
            self._list_items(None)
        self.assertIn('BWENV_SESSION_CACHE is set', stderr.getvalue())

    def test_run_still_strips_the_cached_session_from_the_child(self):
        self.valid_sessions.add('cached_session')
        client = bwenv.BitwardenClient(no_sync=True, session_cache=MemorySessionCache('cached_session'))
        with patch.dict(os.environ, {'APP_SECRET': 'op://Vault/item/field'}):
            with patch.object(client, 'find_item_by_uri_prefix', side_effect=lambda *a: (
                    client._ensure_unlocked(), {"fields": [{"name": "field", "value": "v"}]})[1]):
                env = bwenv.EnvironmentProcessor(client).create_resolved_environment()
        self.assertEqual(client._session, 'cached_session')
        self.assertNotIn('BW_SESSION', env)
        self.assertNotIn('cached_session', env.values())

    def test_lock_forgets_the_cached_session(self):
        cache = MemorySessionCache('cached_session')
        with patch.object(bwenv, 'default_session_cache', return_value=cache), patch('builtins.print'):
            bwenv.lock_session(argparse.Namespace())
        self.assertIsNone(cache.session)


def keyctl_works():
    keyctl = bwenv.shutil.which('keyctl')
    if not keyctl:
        return False
    return subprocess.run([keyctl, 'show', '@u'], capture_output=True).returncode == 0


class TestKeyctlSessionCache(unittest.TestCase):
    """Linux kernel keyring store"""

    def test_session_goes_on_stdin_with_permissions_and_timeout(self):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs.get('input')))
            if command[1] == 'padd':
                return Mock(returncode=0, stdout='123\n', stderr='')
            if command[1] == 'search':
                return Mock(returncode=1, stdout='', stderr='not found')
            return Mock(returncode=0, stdout='', stderr='')

        with patch('subprocess.run', side_effect=run):
            bwenv.KeyctlSessionCache('keyctl').store('the_session', 600)

        padd = [c for c in calls if c[0][1] == 'padd']
        self.assertEqual(padd, [(['keyctl', 'padd', 'user', 'bwenv_session', '@u'], 'the_session')])
        self.assertTrue(all('the_session' not in ' '.join(c[0]) for c in calls))
        self.assertIn((['keyctl', 'setperm', '123', '0x3f3f0000'], None), calls)
        self.assertIn((['keyctl', 'timeout', '123', '600'], None), calls)

    def test_links_the_user_keyring_when_the_key_is_not_possessed(self):
        """Without pam_keyinit (CI, services) setperm is refused until @u is linked into the session keyring"""
        linked = []

        def run(command, **kwargs):
            if command[1] == 'padd':
                return Mock(returncode=0, stdout='123\n', stderr='')
            if command[1] == 'search':
                return Mock(returncode=1, stdout='', stderr='')
            if command[1] == 'link':
                linked.append(command[2:])
            if command[1] == 'setperm' and not linked:
                return Mock(returncode=1, stdout='', stderr='Permission denied')
            return Mock(returncode=0, stdout='', stderr='')

        with patch('subprocess.run', side_effect=run):
            bwenv.KeyctlSessionCache('keyctl').store('the_session', 600)
        self.assertEqual(linked, [['@u', '@s']])

    @unittest.skipUnless(sys.platform.startswith('linux') and keyctl_works(), 'needs a usable keyctl')
    def test_real_keyring_round_trip_and_expiry(self):
        cache = bwenv.KeyctlSessionCache(bwenv.shutil.which('keyctl'), description='bwenv_unittest')
        self.addCleanup(cache.clear)
        cache.store('dummy+session/value==', 1)
        self.assertEqual(cache.load(), 'dummy+session/value==')
        bwenv.time.sleep(2)
        self.assertIsNone(cache.load())
        cache.store('another', 60)
        cache.clear()
        self.assertIsNone(cache.load())


class TestKeychainSessionCache(unittest.TestCase):
    """macOS keychain store"""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp()
        self.addCleanup(bwenv.shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, 'bwenv-test.keychain-db')

    def test_session_and_keychain_password_go_to_security_on_stdin(self):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs.get('input')))
            if command[1] == '-i':
                open(self.path, 'w').close()
            if command[1] == 'find-generic-password':
                return Mock(returncode=0, stdout='the_session\n', stderr='')
            return Mock(returncode=0, stdout='', stderr='')

        with patch('subprocess.run', side_effect=run):
            cache = bwenv.KeychainSessionCache('security', self.path)
            cache.store('the_session', 600)
            self.assertEqual(cache.load(), 'the_session')

        script = [c[1] for c in calls if c[0] == ['security', '-i']][0]
        self.assertIn('-w the_session', script)
        self.assertIn('-t 600', script)
        self.assertTrue(all('the_session' not in ' '.join(c[0]) for c in calls))

    def test_an_expired_keychain_is_deleted_without_reading_it(self):
        open(self.path, 'w').close()
        with open(self.path + '.expires', 'w') as f:
            f.write('1\n')
        with patch('subprocess.run', return_value=Mock(returncode=0, stdout='', stderr='')) as run:
            self.assertIsNone(bwenv.KeychainSessionCache('security', self.path).load())
        self.assertEqual([c[0][0][1] for c in run.call_args_list], ['delete-keychain'])
        self.assertFalse(os.path.exists(self.path + '.expires'))

    @unittest.skipUnless(sys.platform == 'darwin', 'needs macOS')
    def test_real_keychain_round_trip(self):
        cache = bwenv.KeychainSessionCache(bwenv.shutil.which('security'), self.path)
        self.addCleanup(cache.clear)
        cache.store('dummy+session/value==', 60)
        self.assertEqual(cache.load(), 'dummy+session/value==')
        cache.clear()
        self.assertIsNone(cache.load())
        self.assertFalse(os.path.exists(self.path))


class TestDpapiSessionCache(unittest.TestCase):
    """Windows DPAPI file store"""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp()
        self.addCleanup(bwenv.shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, 'bwenv', 'session.bin')

    def _fake_dpapi(self):
        """Reversible stand-in for DPAPI, so the expiry logic is tested on every platform"""
        patchers = [patch.object(bwenv, 'dpapi_protect', side_effect=lambda data, entropy: data[::-1]),
                    patch.object(bwenv, 'dpapi_unprotect', side_effect=lambda data, entropy: data[::-1])]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_round_trip_and_expiry(self):
        self._fake_dpapi()
        cache = bwenv.DpapiSessionCache(self.path)
        cache.store('the_session', 60)
        self.assertEqual(cache.load(), 'the_session')
        with patch.object(bwenv.time, 'time', return_value=bwenv.time.time() + 61):
            self.assertIsNone(cache.load())
        self.assertFalse(os.path.exists(self.path))

    def test_an_unreadable_file_is_discarded(self):
        self._fake_dpapi()
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, 'wb') as f:
            f.write(b'garbage')
        self.assertIsNone(bwenv.DpapiSessionCache(self.path).load())
        self.assertFalse(os.path.exists(self.path))

    @unittest.skipUnless(bwenv.IS_WINDOWS, 'needs Windows')
    def test_real_dpapi_round_trip(self):
        cache = bwenv.DpapiSessionCache(self.path)
        cache.store('dummy+session/value==', 60)
        with open(self.path, 'rb') as f:
            self.assertNotIn(b'dummy+session', f.read())
        self.assertEqual(cache.load(), 'dummy+session/value==')
        cache.clear()
        self.assertIsNone(cache.load())


class FakeVault:
    """A bw CLI with a vault that create/edit really change"""

    def __init__(self, items, folders=(), collections=(), organizations=()):
        self.items = [json.loads(json.dumps(i)) for i in items]
        self.folders = list(folders)
        self.collections = list(collections)
        self.organizations = list(organizations)
        self.calls = []
        self.next_id = 1

    def _new_id(self, prefix):
        self.next_id += 1
        return f"{prefix}-{self.next_id}"

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), kwargs.get('input')))
        args = list(command[1:])
        payload = json.loads(base64.b64decode(kwargs['input'])) if kwargs.get('input') else None
        if args == ['status']:
            out = {"status": "unlocked"}
        elif args[0] == 'list':
            out = {'items': self.items, 'folders': self.folders, 'collections': self.collections,
                   'organizations': self.organizations}[args[1]]
        elif args[:2] == ['get', 'item']:
            out = next(i for i in self.items if i['id'] == args[2])
        elif args == ['create', 'folder']:
            out = dict(payload, id=self._new_id('folder'))
            self.folders.append(out)
        elif args == ['create', 'item']:
            out = dict(payload, id=self._new_id('item'))
            self.items.append(out)
        elif args[:2] == ['edit', 'item']:
            out = payload
            self.items = [payload if i['id'] == args[2] else i for i in self.items]
        else:
            out = ''
        return Mock(returncode=0, stdout=json.dumps(out) if out != '' else '', stderr='')

    def writes(self):
        return [c for c in self.calls if c[0][1] in ('create', 'edit')]

    def item(self, name):
        return next(i for i in self.items if i['name'] == name)


class TestSetCommand(unittest.TestCase):
    """`bwenv set`: store values typed into a masked prompt"""

    SECRET = 'n3w-S3cret-Do-Not-Log'
    ORG = '7e6ff908-4315-4377-9834-7154889cb4c8'
    ITEMS = [
        {"id": "demo", "name": "DEMO_DATA", "organizationId": None, "folderId": "f-demo", "type": 1,
         "login": {"username": "u", "password": "p"},
         "fields": [{"name": "prod/plaintext", "value": "old", "type": 0}, {"name": "keep", "value": "k", "type": 1}]},
        {"id": "twin1", "name": "twin", "organizationId": None, "folderId": "f-demo", "type": 2, "fields": []},
        {"id": "twin2", "name": "twin", "organizationId": None, "folderId": "f-demo", "type": 2, "fields": []},
        {"id": "outer", "name": "Work", "organizationId": None, "folderId": None, "type": 2, "fields": []},
        {"id": "inner", "name": "app", "organizationId": None, "folderId": "f-work", "type": 2, "fields": []},
    ]
    FOLDERS = [{"id": "f-demo", "name": "Demo/Data"}, {"id": "f-work", "name": "Work"}]
    COLLECTIONS = [{"id": "c-1", "name": "Team", "organizationId": ORG}]

    def setUp(self):
        self.vault = FakeVault(self.ITEMS, self.FOLDERS, self.COLLECTIONS)
        patcher = patch('subprocess.run', side_effect=self.vault)
        patcher.start()
        self.addCleanup(patcher.stop)
        env_patcher = patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        ask = patch.object(bwenv, 'ask_secret_value', return_value=self.SECRET)
        self.ask = ask.start()
        self.addCleanup(ask.stop)

    def _set(self, *uris):
        args = argparse.Namespace(uri=list(uris), no_sync=True)
        with patch('sys.stderr', new_callable=io.StringIO) as stderr, self.assertLogs(level='DEBUG') as logs:
            logging.getLogger().debug("set test start")
            try:
                bwenv.set_secrets(args)
                code = 0
            except SystemExit as e:
                code = e.code
        output = stderr.getvalue() + '\n'.join(logs.output)
        self.assertNotIn(self.SECRET, output)
        for command, _ in self.vault.calls:
            self.assertNotIn(self.SECRET, ' '.join(command), "values must not be on the command line")
        return code, stderr.getvalue()

    def test_adds_a_hidden_field_and_keeps_the_others(self):
        code, _ = self._set('bw://myvault/Demo/Data/DEMO_DATA/API_TOKEN')
        self.assertEqual(code, 0)
        item = self.vault.item('DEMO_DATA')
        self.assertIn({"name": "API_TOKEN", "value": self.SECRET, "type": 1, "linkedId": None}, item['fields'])
        self.assertIn({"name": "keep", "value": "k", "type": 1}, item['fields'])
        self.assertEqual(item['login'], {"username": "u", "password": "p"})
        self.assertEqual([c[0] for c in self.vault.writes()], [['bw', 'edit', 'item', 'demo']])

    def test_replaces_an_existing_field_with_a_slash_in_its_name(self):
        code, _ = self._set('bw://myvault/Demo/Data/DEMO_DATA/prod/plaintext')
        self.assertEqual(code, 0)
        fields = self.vault.item('DEMO_DATA')['fields']
        self.assertIn({"name": "prod/plaintext", "value": self.SECRET, "type": 0}, fields)
        self.assertIn('(replace)', self.ask.call_args[0][0])

    def test_sets_the_login_password(self):
        self._set('bw://myvault/Demo/Data/DEMO_DATA/password')
        self.assertEqual(self.vault.item('DEMO_DATA')['login']['password'], self.SECRET)

    def test_creates_the_folder_and_a_secure_note(self):
        code, _ = self._set('bw://myvault/New/Place/svc/TOKEN')
        self.assertEqual(code, 0)
        folder = next(f for f in self.vault.folders if f['name'] == 'New/Place')
        item = self.vault.item('svc')
        self.assertEqual((item['type'], item['folderId'], item['organizationId']), (2, folder['id'], None))
        self.assertEqual(item['fields'], [{"name": "TOKEN", "value": self.SECRET, "type": 1, "linkedId": None}])
        self.assertEqual([c[0] for c in self.vault.writes()],
                         [['bw', 'create', 'folder'], ['bw', 'create', 'item']])

    def test_several_fields_of_a_new_item_make_one_item(self):
        self._set('bw://myvault/Demo/Data/svc/A', 'bw://myvault/Demo/Data/svc/B')
        self.assertEqual([c[0] for c in self.vault.writes()], [['bw', 'create', 'item']])
        self.assertEqual([f['name'] for f in self.vault.item('svc')['fields']], ['A', 'B'])

    def test_creates_an_organization_item_in_its_collection(self):
        self.vault.organizations = [{"id": self.ORG, "name": "DICE.fm"}]
        self._set('bw://DICE.fm/Team/svc/TOKEN')
        item = self.vault.item('svc')
        self.assertEqual((item['organizationId'], item['collectionIds'], item['folderId']), (self.ORG, ['c-1'], None))

    def test_refuses_a_missing_collection(self):
        code, stderr = self._set(f'bw://{self.ORG}/Nowhere/svc/TOKEN')
        self.assertEqual(code, 1)
        self.assertIn("does not create collections", stderr)
        self.assertEqual(self.vault.writes(), [])

    def test_refuses_an_ambiguous_item_before_asking(self):
        code, stderr = self._set('bw://myvault/Demo/Data/twin/TOKEN')
        self.assertEqual(code, 1)
        self.assertIn("2 items named 'twin'", stderr)
        self.ask.assert_not_called()
        self.assertEqual(self.vault.writes(), [])

    def test_refuses_a_uri_that_fits_two_items(self):
        """bw://myvault/Work/app/TOKEN could be field app/TOKEN of item Work, or TOKEN of app in folder Work"""
        code, stderr = self._set('bw://myvault/Work/app/TOKEN')
        self.assertEqual(code, 1)
        self.assertIn("more than one item", stderr)
        self.assertEqual(self.vault.writes(), [])

    def test_refuses_to_guess_between_an_existing_item_and_a_new_one(self):
        """With item Work at the top level, bw://myvault/Work/svc/A could be its field svc/A or a new item svc"""
        code, stderr = self._set('bw://myvault/Work/svc/A')
        self.assertEqual(code, 1)
        self.assertIn("field 'svc/A' of 'Work'", stderr)
        self.assertIn("a new item 'svc' in 'Work'", stderr)
        self.assertEqual(self.vault.writes(), [])

    def test_a_folder_id_settles_it(self):
        code, _ = self._set('bw://myvault/f-work/svc/A')
        self.assertEqual(code, 0)
        self.assertEqual(self.vault.item('svc')['folderId'], 'f-work')

    def test_refuses_op_uris(self):
        code, stderr = self._set('op://Personal/demo/field')
        self.assertEqual(code, 1)
        self.assertIn("bw:// URIs", stderr)

    def test_a_later_read_in_the_same_run_sees_the_new_value(self):
        client = bwenv.BitwardenClient(no_sync=True)
        target = client.plan_field_write('bw://myvault/Demo/Data/DEMO_DATA/prod/plaintext')
        client.write_fields(target, {target.field: 'fresh'})
        self.assertEqual(client.resolve_bw_uri_to_value('bw://myvault/Demo/Data/DEMO_DATA/prod/plaintext'), 'fresh')
        new = client.plan_field_write('bw://myvault/Other/svc/TOKEN')
        client.write_fields(new, {'TOKEN': 'brand new'})
        self.assertEqual(client.resolve_bw_uri_to_value('bw://myvault/Other/svc/TOKEN'), 'brand new')


class TestAskSecretValue(unittest.TestCase):
    """The masked prompt for a value to store"""

    def _ask(self, prompt, tty, **patches):
        with patch.dict(os.environ, {'BWENV_PROMPT': prompt}), patch('sys.stdin') as stdin:
            stdin.isatty.return_value = tty
            return bwenv.ask_secret_value('Value for X:')

    def test_terminal_uses_getpass(self):
        with patch('getpass.getpass', return_value='typed') as getpass_mock:
            self.assertEqual(self._ask('auto', True), 'typed')
        getpass_mock.assert_called_once()

    def test_no_terminal_uses_the_dialog(self):
        with patch.object(bwenv, 'ask_password_in_dialog', return_value='boxed'):
            self.assertEqual(self._ask('auto', False), 'boxed')

    def test_cancel_empty_and_none_store_nothing(self):
        with patch.object(bwenv, 'ask_password_in_dialog', return_value=None):
            self.assertRaisesRegex(bwenv.BWEnvError, 'Cancelled', self._ask, 'gui', False)
        with patch.object(bwenv, 'ask_password_in_dialog', return_value=''):
            self.assertRaisesRegex(bwenv.BWEnvError, 'empty', self._ask, 'gui', False)
        self.assertRaisesRegex(bwenv.BWEnvError, 'BWENV_PROMPT=none', self._ask, 'none', True)
        with patch.object(bwenv, 'ask_password_in_dialog', side_effect=bwenv.NoPasswordDialog()):
            self.assertRaisesRegex(bwenv.BWEnvError, 'cannot ask', self._ask, 'auto', False)


class TestEnvFileParsing(unittest.TestCase):
    """KEY=VALUE files for `bwenv import`"""

    def test_dotenv_syntax(self):
        text = '\n'.join([
            '# a comment', '', 'PLAIN=value', 'export EXPORTED=yes', '  SPACED = padded  ',
            'COMMENTED=abc # trailing', 'HASH=a#b', "SINGLE='lit $HOME \\n'", 'DOUBLE="a \\"q\\" \\n\\\\"',
            'EMPTY=', 'QUOTED_COMMENT="x" # note', 'PLAIN=last wins',
        ])
        self.assertEqual(bwenv.parse_env_file(text), {
            'PLAIN': 'last wins', 'EXPORTED': 'yes', 'SPACED': 'padded', 'COMMENTED': 'abc', 'HASH': 'a#b',
            'SINGLE': 'lit $HOME \\n', 'DOUBLE': 'a "q" \n\\', 'EMPTY': '', 'QUOTED_COMMENT': 'x',
        })

    def test_errors_name_the_line_but_never_the_value(self):
        for text, message in (('GOOD=1\nnot a pair s3cret', 'Line 2'), ('KEY="s3cret', 'unterminated'),
                              ("KEY='a' s3cret", 'after its closing quote')):
            with self.assertRaises(bwenv.BWEnvError) as raised:
                bwenv.parse_env_file(text)
            self.assertIn(message, str(raised.exception))
            self.assertNotIn('s3cret', str(raised.exception))


class TestImportCommand(unittest.TestCase):
    """`bwenv import`: move a .env file into an item"""

    def setUp(self):
        import tempfile
        self.vault = FakeVault(TestSetCommand.ITEMS, TestSetCommand.FOLDERS)
        patcher = patch('subprocess.run', side_effect=self.vault)
        patcher.start()
        self.addCleanup(patcher.stop)
        env_patcher = patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        handle, self.env_file = tempfile.mkstemp(suffix='.env')
        os.close(handle)
        self.addCleanup(os.remove, self.env_file)
        with open(self.env_file, 'w') as f:
            f.write('# app\nDB_PASSWORD="pa ss"\nexport API_KEY=k-123\n')

    def _import(self, uri):
        with patch('sys.stdout', new_callable=io.StringIO) as stdout, \
                patch('sys.stderr', new_callable=io.StringIO) as stderr:
            try:
                bwenv.import_env_file(argparse.Namespace(uri=uri, file=self.env_file, no_sync=True))
                code = 0
            except SystemExit as e:
                code = e.code
        return code, stdout.getvalue(), stderr.getvalue()

    def test_creates_the_item_and_prints_references(self):
        code, stdout, _ = self._import('bw://myvault/Work/myapp')
        self.assertEqual(code, 0)
        item = self.vault.item('myapp')
        self.assertEqual({f['name']: (f['value'], f['type']) for f in item['fields']},
                         {'DB_PASSWORD': ('pa ss', 1), 'API_KEY': ('k-123', 1)})
        self.assertEqual(stdout, 'DB_PASSWORD=bw://myvault/Work/myapp/DB_PASSWORD\n'
                                 'API_KEY=bw://myvault/Work/myapp/API_KEY\n')
        for command, _ in self.vault.calls:
            self.assertNotIn('k-123', ' '.join(command))

    def test_updates_an_existing_item(self):
        code, _, _ = self._import('bw://myvault/Demo/Data/DEMO_DATA')
        self.assertEqual(code, 0)
        names = [f['name'] for f in self.vault.item('DEMO_DATA')['fields']]
        self.assertEqual(names, ['prod/plaintext', 'keep', 'DB_PASSWORD', 'API_KEY'])

    def test_refuses_an_ambiguous_item(self):
        code, _, stderr = self._import('bw://myvault/Demo/Data/twin')
        self.assertEqual(code, 1)
        self.assertIn("2 items named 'twin'", stderr)
        self.assertEqual(self.vault.writes(), [])


if __name__ == '__main__':
    unittest.main()