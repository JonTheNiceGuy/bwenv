# bwenv - Bitwarden Environment Variable Processor

A cross-platform command-line tool that replaces environment variables containing Bitwarden secret references with actual secret values using the Bitwarden CLI.

## Features

- **Seamless Integration**: Works with any command or application that uses environment variables
- **Secure**: Uses the official Bitwarden CLI for authentication and secret retrieval
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **URI-Based**: Simple URI style syntax for referencing secrets (see below for details)
- **Interactive Authentication**: Automatically prompts for master password when needed
- **Flexible Flag Positions**: Global flags like `--debug` and `--no-sync` can be placed before or after subcommands
- **Debug Support**: Built-in debug mode for troubleshooting

## Prerequisites

- Python 3.6 or higher
- [Bitwarden CLI](https://bitwarden.com/help/cli/) installed and accessible in PATH
- Bitwarden account with vault access

## Installation

1. Download `bwenv.py` from this repository
2. Make it executable: `chmod +x bwenv.py`
3. Optionally, rename to `bwenv` and place in your PATH for easier access

## Usage

### Basic Syntax

```bash
# Flags can be placed before or after the subcommand
bwenv [--no-sync] [--debug] run <command> [args...]  
bwenv [--no-sync] run [--debug] <command> [args...]  
bwenv [--debug] run [--no-sync] <command> [args...]
bwenv run [--no-sync] [--debug] <command> [args...]
bwenv [--no-sync] [--debug] run -- <command> [args...]  
bwenv [--no-sync] run [--debug] -- <command> [args...]  
bwenv [--debug] run [--no-sync] -- <command> [args...]
bwenv run [--no-sync] [--debug] -- <command> [args...]

# Read command supports flexible flag positions too
bwenv [--no-sync] [--debug] read <uri>
bwenv [--no-sync] read [--debug] <uri>
bwenv read [--no-sync] [--debug] <uri>
```

### URI Formats

Reference secrets using one of these supported formats:

#### 1Password Compatible Format
`op://vault_name/item_name/field_name`

- `vault_name`: Name of your Bitwarden vault or organization
- `item_name`: Name of the item containing the secret
- `field_name`: Field name within the item (supports custom fields, `username`, `password`)

#### Bitwarden Native Format
`bw://vault_or_org/folder_or_collection/item_name/field_name`

- `vault_or_org`: Vault name, organization name, or UUID
- `folder_or_collection`: Folder name, collection name, or UUID (use "myvault" or "unassigned" for personal vault items)
- `item_name`: Name of the item containing the secret
- `field_name`: Field name within the item

**Special identifiers:**
- Use `myvault` or `unassigned` for personal vault items
- UUIDs can be used instead of names for more precise targeting

### Examples

#### Run a command with secret environment variables:
```bash
# Set environment variable with secret reference
export DATABASE_PASSWORD="op://Production/database/password"
export ACCOUNT_TOKEN="bw://myvault/CustomerA/ProjectB/Service Item/prod/token"

# Run application with resolved secrets
bwenv run python app.py
```

#### Read a specific secret:
```bash
bwenv read op://Production/api-keys/stripe_secret
bwenv read "bw://example.org/collection1/service/username"
```

#### Use debug mode:
```bash
# Global flag position
bwenv --debug run python app.py

# Subcommand flag position  
bwenv run --debug python app.py
```

#### Skip vault sync for faster execution:
```bash
# Global flag position
bwenv --no-sync run python app.py

# Subcommand flag position
bwenv run --no-sync python app.py
```

#### Use command separator to isolate flags:
```bash
# bwenv flags before --, command flags after
bwenv --no-sync run -- python app.py --debug

# Equivalent without separator (original syntax)
bwenv --no-sync run python app.py --debug
```

#### Complex example:
```bash
# Set multiple secret references
export DB_USER="op://Production/database/username"
export DB_PASS="bw://Acme-Inc/DB Team/production db/password"
export API_KEY="op://Production/api-keys/service_key"

# Run with debug and skip sync for faster execution
bwenv --debug --no-sync run docker-compose up

# Use separator to pass flags to docker-compose
bwenv --debug run -- docker-compose up --build
```

## Authentication

The tool handles Bitwarden authentication automatically:

1. **First run**: You'll need to log in with `bw login`
2. **Locked vault**: The tool will prompt for your master password
3. **Session management**: Session tokens are automatically managed
4. **No interaction needed**: Once authenticated, subsequent runs work seamlessly

## Field Types

The tool supports various field types:

- **Login fields**: `username`, `password`
- **Custom fields**: Any custom field name you've defined
- **Notes**: Use the field name as defined in your item

## Command Line Options

- `--no-sync`: Skip syncing the Bitwarden vault before processing secrets (default behavior syncs)
- `--debug`: Enable verbose debug output for troubleshooting
- `--help`: Show help information
- `--`: Command separator to isolate bwenv flags from command flags

Flags can be placed either before or after the subcommand for flexibility. Use `--` after the `run` command to ensure that any flags following it are passed to your command rather than interpreted by bwenv.

## Testing

Run the included unit tests:

```bash
python -m unittest test_bwenv.py -v
```

## Security Considerations

- Secrets are only held in memory temporarily during command execution
- No secrets are logged or written to disk
- Uses official Bitwarden CLI for all vault operations
- Session tokens are managed securely

## Troubleshooting

### Common Issues

1. **"bw not found"**: Install the Bitwarden CLI
2. **"You are not logged in"**: Run `bw login` first
3. **"Master password required"**: The tool will prompt automatically
4. **"No item found"**: Check your vault name, item name, and field name
5. **"Field not found"**: Verify the field exists in the specified item

### Debug Mode

Use `--debug` flag to see detailed operation logs with comprehensive debugging information:

```bash
bwenv --debug read op://vault/item/field
```

Debug output includes:
- **Command parsing**: Arguments, Python version, working directory
- **Environment scanning**: Discovery of op:// URIs in environment variables
- **Bitwarden CLI operations**: Command execution with timing and response details
- **Authentication status**: BW_SESSION presence and authentication flow
- **Item resolution**: Vault searches, item matching, and field lookups
- **Performance metrics**: Sync timing and operation durations
- **Value handling**: Safe previews of resolved secrets (truncated for security)

Example debug output:
```
[DEBUG 15:55:14] Debug mode enabled
[DEBUG 15:55:14] Command: run
[DEBUG 15:55:14] BW_SESSION present: True
[DEBUG 15:55:14] Found 2 environment variables with op:// URIs
[DEBUG 15:55:15] Vault sync completed in 1.70 seconds
[DEBUG 15:55:19] Found matching item: DEMO_DATA (ID: aaaaaaaa-1111-bbbb-2222-cccccccccccc)
[DEBUG 15:55:19] Successfully resolved URI to value (length: 22 chars)
```

## License

This software is released into the public domain under the [Unlicense](UNLICENSE).

## Important Disclaimers

**No Warranty**: This software is provided "as is" without any warranty of any kind. There is no assertion that this code is free from bugs, errors, or security vulnerabilities.

**Not for Critical Use**: This software should **NOT** be used for mission-critical applications, safety-focused systems, or life-altering situations. It has been developed and tested only as a personal passion project and has not undergone the rigorous testing required for production or critical systems.

**Use at Your Own Risk**: Users assume all responsibility for testing, validation, and risk assessment before deploying this software in any environment.

## AI Assistance Disclosure

This code was developed with assistance from AI tools. While released under a permissive license that allows unrestricted reuse, we acknowledge that portions of the implementation may have been influenced by AI training data. Should any copyright assertions or claims arise regarding uncredited imported code, the affected portions will be promptly rewritten to remove or properly credit any unlicensed or uncredited work.

## Contributing

Contributions are welcome! Since this is public domain software:

- No copyright assignment needed
- Submit issues and pull requests freely
- All contributions will be released under the same public domain dedication
- **Feature requests and improvements are gratefully received**, however they may not be implemented due to time constraints or if they don't align with the developer's vision for the project

## Support

This is a community project. For support:

1. Check the troubleshooting section above
2. Review debug output when using `--debug` flag
3. Open an issue with detailed information about your problem

## Changelog

- **v1.0**: Initial release with basic functionality
- **v1.1**: Added authentication handling and interactive password prompts
- **v1.2**: Added flexible flag positioning support
- **v1.3**: Consolidated into single file, improved error handling
- **v1.4**: Default to sync on every run, rather than when specified
- **v1.5**: Added `--` command separator to isolate bwenv flags from command flags. Both `./bwenv.py run echo "hello"` and `./bwenv.py run -- echo "hello"` work identically, but `./bwenv.py --no-sync run -- echo --debug "hello"` properly separates bwenv flags from command flags.
- **v1.6**: Enhanced debug functionality with comprehensive logging including timestamps, command execution details, performance metrics, authentication status, item resolution tracking, and safe value previews.
- **v1.7**: Fixed argument parsing to ensure consistent behavior regardless of flag positions. All flag combinations (`--debug run`, `run --debug`, etc.) now work identically while properly respecting the `--` separator boundary.
- **v1.8**: Added support for Bitwarden native URI format (`bw://`) alongside existing 1Password-compatible format (`op://`). The new format supports organization/collection paths, personal vault items, and UUID-based targeting for precise item resolution.