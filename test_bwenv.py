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
        mock_run.return_value = Mock(stdout="test output", returncode=0)
        
        client = bwenv.BitwardenClient()
        result = client._run_bw_command(['list', 'items'])
        
        self.assertEqual(result, "test output")
        mock_run.assert_called_once_with(
            ['bw', 'list', 'items'],
            capture_output=True,
            text=True,
            check=True
        )
    
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
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_sync_vault(self, mock_run):
        """Test vault synchronization"""
        mock_run.return_value = Mock(stdout="Syncing complete.", returncode=0)
        
        client = bwenv.BitwardenClient()
        client.sync_vault()
        
        mock_run.assert_called_once_with(
            ['bw', 'sync'],
            capture_output=True,
            text=True,
            check=True
        )
    
    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_get_items_with_op_uris(self, mock_run):
        """Test filtering items with op:// URIs"""
        mock_run.return_value = Mock(stdout=json.dumps(self.sample_items), returncode=0)
        
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
        mock_run.return_value = Mock(stdout=json.dumps(self.sample_items), returncode=0)
        
        client = bwenv.BitwardenClient(no_sync=False)
        items = client.get_items_with_op_uris()
        
        # Should call sync first, then list items
        self.assertEqual(mock_run.call_count, 2)
        mock_run.assert_any_call(['bw', 'sync'], capture_output=True, text=True, check=True)
        mock_run.assert_any_call(['bw', 'list', 'items', '--search', 'op://'], capture_output=True, text=True, check=True)
    
    @patch('subprocess.run')
    @patch.dict(os.environ, {'BW_SESSION': 'test_session_token'})
    def test_find_item_by_uri_prefix(self, mock_run):
        """Test finding item by URI prefix"""
        mock_run.return_value = Mock(stdout=json.dumps(self.sample_items), returncode=0)
        
        client = bwenv.BitwardenClient()
        
        # Find existing item
        item = client.find_item_by_uri_prefix("Employee", "example")
        self.assertIsNotNone(item)
        self.assertEqual(item['id'], 'item1')
        
        # Try to find non-existing item
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
        'ANOTHER_NORMAL': 'another_value'
    }, clear=True)
    def test_scan_environment(self):
        """Test scanning environment for op:// URIs"""
        op_vars = self.processor.scan_environment()
        
        expected = {
            'OP_VAR1': 'op://Employee/example/secret',
            'OP_VAR2': 'op://My Vault/My Item/api_key'
        }
        self.assertEqual(op_vars, expected)
    
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


if __name__ == '__main__':
    unittest.main()