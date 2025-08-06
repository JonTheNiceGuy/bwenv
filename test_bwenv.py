#!/usr/bin/env python3
"""
Unit tests for bwenv script
"""

import json
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
    
    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_run_bw_command_success(self, mock_run):
        """Test successful Bitwarden CLI command execution"""
        # Mock both status call and actual command
        mock_run.side_effect = [
            Mock(stdout='{"status":"unlocked"}', returncode=0),  # bw status call
            Mock(stdout="test output", returncode=0)  # actual command
        ]
        
        client = bwenv.BitwardenClient()
        result = client._run_bw_command(['list', 'items'])
        
        self.assertEqual(result, "test output")
        # Should now make two calls: status validation + actual command
        self.assertEqual(mock_run.call_count, 2)
        mock_run.assert_any_call(['bw', 'status'], capture_output=True, text=True, check=True)
        mock_run.assert_any_call(['bw', 'list', 'items'], capture_output=True, text=True, check=True)
    
    @patch('subprocess.run')
    def test_run_bw_command_failure(self, mock_run):
        """Test Bitwarden CLI command failure"""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ['bw', 'list', 'items'], stderr="Authentication required"
        )
        
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
    @patch.dict(os.environ, {'BW_SESSION': 'expired_session_token'})
    def test_session_validation_clears_expired_session(self, mock_run):
        """Test that session validation clears expired BW_SESSION"""
        # Mock status call indicating unauthenticated (expired session)
        mock_run.return_value = Mock(stdout='{"status":"unauthenticated"}', returncode=0)
        
        client = bwenv.BitwardenClient()
        
        # Just test the validation method directly
        client._validate_session()
        
        # Verify that BW_SESSION was cleared during validation
        self.assertNotIn('BW_SESSION', os.environ)
    
    @patch('subprocess.run')  
    @patch.dict(os.environ, {'BW_SESSION': 'locked_session_token'})
    def test_session_validation_unlocks_locked_vault(self, mock_run):
        """Test that session validation unlocks a locked vault"""
        # Mock status call indicating locked, then successful unlock
        mock_run.side_effect = [
            Mock(stdout='{"status":"locked"}', returncode=0),  # bw status call
            Mock(stdout='new_session_token_123', returncode=0)  # bw unlock --raw call
        ]
        
        client = bwenv.BitwardenClient()
        
        # Mock stdin to avoid interactive prompt in test
        with patch('sys.stdin'):
            client._validate_session()
        
        # Verify that BW_SESSION was updated with new token
        self.assertEqual(os.environ.get('BW_SESSION'), 'new_session_token_123')
    
    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_sync_vault(self, mock_run):
        """Test vault synchronization"""
        # Mock both status call and sync command
        mock_run.side_effect = [
            Mock(stdout='{"status":"unlocked"}', returncode=0),  # bw status call
            Mock(stdout="Syncing complete.", returncode=0)  # bw sync call
        ]
        
        client = bwenv.BitwardenClient()
        client.sync_vault()
        
        # Should now make two calls: status validation + sync
        self.assertEqual(mock_run.call_count, 2)
        mock_run.assert_any_call(['bw', 'status'], capture_output=True, text=True, check=True)
        mock_run.assert_any_call(['bw', 'sync'], capture_output=True, text=True, check=True)
    
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
            elif command == ['bw', 'list', 'items', '--search', 'op://']:
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
            elif command == ['bw', 'list', 'items', '--search', 'op://']:
                return Mock(stdout=json.dumps(self.sample_items), returncode=0)
            else:
                return Mock(stdout="", returncode=0)
        
        mock_run.side_effect = mock_command_response
        
        client = bwenv.BitwardenClient(no_sync=False)
        items = client.get_items_with_op_uris()
        
        # Should call status validation, sync, then list items
        mock_run.assert_any_call(['bw', 'status'], capture_output=True, text=True, check=True)
        mock_run.assert_any_call(['bw', 'sync'], capture_output=True, text=True, check=True)
        mock_run.assert_any_call(['bw', 'list', 'items', '--search', 'op://'], capture_output=True, text=True, check=True)
    
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
            elif command == ['bw', 'list', 'items', '--search', 'op://']:
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
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ['bw', 'list', 'items'], stderr="You are not logged in"
        )
        
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


if __name__ == '__main__':
    unittest.main()