#!/usr/bin/env python3
"""
Unit tests for bwenv script
"""

import argparse
import base64
import datetime
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
    
    @unittest.skipUnless(os.environ.get('TEST_ORG_NAME'), "TEST_ORG_NAME environment variable not set")
    def test_parse_bw_uri_with_org_name(self):
        """Test parsing bw:// URIs with real org name from environment"""
        org_name = os.environ.get('TEST_ORG_NAME')
        uri = f"bw://{org_name}/Demo/Data/DEMO_DATA/password"
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
        return [c.args[0] for c in mock_run.call_args_list]

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
            self.assertEqual(call.kwargs['env']['BW_SESSION'], 'test_session_token')
            self.assertEqual(call.kwargs['encoding'], 'utf-8')
            self.assertGreater(call.kwargs['timeout'], 0)

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

        self.assertEqual({c.kwargs['timeout'] for c in mock_run.call_args_list}, {5.0})

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
        list_calls = [c for c in mock_run.call_args_list if c.args[0][:2] == ['bw', 'list']]
        self.assertTrue(all(c.kwargs['env']['BW_SESSION'] == 'new_session_token_123' for c in list_calls))
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

        self.assertTrue(all(c.args[0][0] == 'C:\\npm\\bw.cmd' for c in mock_run.call_args_list))

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
        self.assertEqual([c.args[0] for c in mock_run.call_args_list],
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

        commands = [c.args[0] for c in mock_run.call_args_list]
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

        commands = [c.args[0] for c in mock_run.call_args_list]
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

        commands = [c.args[0] for c in mock_run.call_args_list]
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
        commands = [c.args[0] for c in self.mock_run.call_args_list]
        self.assertEqual(commands.count(['bw', 'list', 'folders']), 1)
        self.assertEqual(commands.count(['bw', 'list', 'collections']), 1)



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


class TestFunctional(unittest.TestCase):
    """Functional tests for the complete bwenv workflow"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_script = ['python', os.path.join(os.path.dirname(__file__), 'bwenv.py')]
    
    def test_script_help(self):
        """Test that the script shows help correctly"""
        result = subprocess.run(self.test_script + ['--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Bitwarden Environment Variable Processor", result.stdout)
        self.assertIn("run", result.stdout)
        self.assertIn("read", result.stdout)
    
    def test_script_no_args(self):
        """Test script behavior with no arguments"""
        result = subprocess.run(self.test_script, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("usage:", result.stdout)
    
    def test_run_command_no_command(self):
        """Test run subcommand with no command specified"""
        result = subprocess.run(self.test_script + ['run'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("No command specified", result.stderr)
    
    @patch.dict(os.environ, {'TEST_VAR': 'normal_value'}, clear=True)
    def test_run_command_no_op_vars(self):
        """Test running command when no op:// variables are present"""
        # This should work since there are no op:// vars to resolve
        result = subprocess.run(self.test_script + ['run', 'echo', 'test'], 
                              capture_output=True, text=True)
        # The script should succeed because no BW lookup is needed
        self.assertEqual(result.returncode, 0)
    
    @patch.dict(os.environ, {'TEST_VAR': 'normal_value'}, clear=True)
    def test_run_command_with_separator_no_op_vars(self):
        """Test running command with '--' separator when no op:// variables are present"""
        result = subprocess.run(self.test_script + ['run', '--', 'echo', 'test'], 
                              capture_output=True, text=True)
        # The script should succeed because no BW lookup is needed
        self.assertEqual(result.returncode, 0)
        self.assertIn('test', result.stdout)
    
    @patch.dict(os.environ, {'TEST_VAR': 'normal_value'}, clear=True)
    def test_separator_flag_isolation(self):
        """Test that flags are properly isolated by '--' separator"""
        result = subprocess.run(self.test_script + ['--no-sync', 'run', '--', 'echo', '--help'], 
                              capture_output=True, text=True)
        # Should succeed and echo '--help' (not show bwenv help)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--help', result.stdout)
        self.assertNotIn('usage:', result.stdout)
    
    @patch.dict(os.environ, {'TEST_VAR': 'normal_value'}, clear=True)
    def test_backward_compatibility(self):
        """Test that existing usage patterns still work"""
        # Test original flag usage
        result = subprocess.run(self.test_script + ['--no-sync', 'run', 'echo', 'backward_compat'], 
                              capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('backward_compat', result.stdout)
        
        # Test subcommand flags
        result = subprocess.run(self.test_script + ['run', '--no-sync', 'echo', 'subcommand_flags'], 
                              capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('subcommand_flags', result.stdout)


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
        return [c.args[0] for c in mock_print.call_args_list], '\n'.join(logs.output)

    def _created_sends(self):
        sends = []
        for call in self.mock_run.call_args_list:
            if call.args[0][1:3] == ['send', 'create']:
                self.assertEqual(call.args[0], ['bw', 'send', 'create'], "payload must not be on the command line")
                sends.append(json.loads(base64.b64decode(call.kwargs['input'])))
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
        self.assertNotIn(['bw', 'encode'], [c.args[0] for c in self.mock_run.call_args_list])
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

        written = ''.join(str(c.args[0]) for c in mock_stderr.write.call_args_list)
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
        self.test_script = ['python', os.path.join(os.path.dirname(__file__), 'bwenv.py')]
    
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


if __name__ == '__main__':
    unittest.main()