# bwenv - Bitwarden Environment Variable Processor

A cross-platform command-line tool that replaces environment variables containing Bitwarden secret references with actual secret values using the Bitwarden CLI.

## Features

- **Seamless Integration**: Works with any command or application that uses environment variables
- **Secure**: Uses the official Bitwarden CLI for authentication and secret retrieval
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **URI-Based**: Simple URI style syntax for referencing secrets (see below for details)
- **Interactive Authentication**: Automatically prompts for master password when needed, in the terminal or in a desktop password box
- **Flexible Flag Positions**: Global flags like `--debug` and `--no-sync` can be placed before or after subcommands
- **Debug Support**: Built-in debug mode for troubleshooting that never prints secret values
- **Secret Sharing**: `bwenv send` turns a reference into a single-use Bitwarden Send link
- **Storing Secrets**: `bwenv set` asks for a value in a masked prompt and stores it; `bwenv import` moves a `.env` file into the vault
- **Session Cache**: `BWENV_SESSION_CACHE=8h` keeps the unlocked vault for later runs, in the kernel keyring, a keychain or a DPAPI file

## Prerequisites

- Python 3.7 or higher (tested on 3.7 and the latest release, on Linux, macOS and Windows)
- [Bitwarden CLI](https://bitwarden.com/help/cli/) installed and accessible in PATH
- Bitwarden account with vault access

## Installation

Every release on the [releases page](https://github.com/JonTheNiceGuy/bwenv/releases) carries `bwenv.py`
and its `bwenv.py.sha256` checksum. Install it whichever way suits you.

### Homebrew (macOS and Linux)

```bash
brew install JonTheNiceGuy/bwenv/bwenv
```

This installs `bwenv` with the Bitwarden CLI as a dependency, from the
[JonTheNiceGuy/homebrew-bwenv](https://github.com/JonTheNiceGuy/homebrew-bwenv) tap, which is updated
automatically on each release. Upgrade with `brew update && brew upgrade bwenv`.

### bin

With [marcosnils/bin](https://github.com/marcosnils/bin), which installs and updates binaries straight from
GitHub releases:

```bash
bin install github.com/JonTheNiceGuy/bwenv ~/.local/bin/bwenv
```

Give the destination path so the command is called `bwenv` rather than `bwenv.py`. `bin update` picks up
new releases. You need the [Bitwarden CLI](https://bitwarden.com/help/cli/) installed separately.

### Manually

1. Download `bwenv.py` from the [latest release](https://github.com/JonTheNiceGuy/bwenv/releases/latest)
   (and check it with `sha256sum -c bwenv.py.sha256`)
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

# Send command
bwenv [--no-sync] [--debug] send [--name <title>] [--max-access N] [--expire-hours H] <uri> [<uri>...]

# Store secrets
bwenv [--no-sync] [--debug] set <bw-uri> [<bw-uri>...]
bwenv [--no-sync] [--debug] import <bw-item-uri> <file|->

# Forget the cached session
bwenv lock
```

For `run`, bwenv's flags are recognised only up to the start of your command (or the first `--`).
Everything after that belongs to your command, unchanged: `bwenv run grep --debug f` passes `--debug`
to `grep`, and `bwenv run -- npm run build` runs `npm run build`.

### URI Formats

Reference secrets using one of these supported formats:

#### 1Password Compatible Format
`op://vault_name/item_name/field_name`

- `vault_name`: Name of your Bitwarden vault or organization
- `item_name`: Name of the item containing the secret
- `field_name`: Field name within the item (supports custom fields, `username`, `password`)

bwenv finds the item whose website URI is exactly `op://vault_name/item_name` (`op://Prod/db` does not
match an item with `op://Prod/db-prod`). If two items carry the same reference, bwenv stops with an error
rather than picking one.

#### Bitwarden Native Format
`bw://vault_or_org/folder_or_collection/item_name/field_name`

- `vault_or_org`: Vault name, organization name, or UUID
- `folder_or_collection`: Folder name, collection name, or UUID (use "myvault" or "unassigned" for personal vault items). Optional when the item name is unique.
- `item_name`: Name of the item containing the secret
- `field_name`: Field name within the item

**Special identifiers:**
- Use `myvault` or `unassigned` for personal vault items
- UUIDs can be used instead of names for more precise targeting

**Folder and collection matching:**
- The folder (personal vault) or collection (organization) must match exactly: its full name, such as `Demo/Data` for a nested collection, or its UUID. One segment of a nested name does not match.
- A folder or collection that does not exist is an error; bwenv never falls back to a same-named item elsewhere.
- Without a folder or collection, the item name must be unique in that vault or organization. If two items share the name, bwenv stops with an error asking for the folder or collection rather than guessing.

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

#### Share a secret as a Bitwarden Send:
```bash
# One field, as text
bwenv send op://Production/api-keys/stripe_secret

# A whole item (username, password and custom fields) as JSON
bwenv send "bw://myvault/Demo/Data/DEMO_DATA"

# Loosen the defaults: three views, valid for two hours, with a title
bwenv send --max-access 3 --expire-hours 2 --name "For the on-call engineer" op://Production/database/password
```

By default a Send can be opened **once**, is deleted after **24 hours**, hides its text until the
recipient reveals it, hides your email address, and is named "Shared secret" so the link does not reveal
the reference. `--max-access 0` allows unlimited views. With several URIs, each Send is named
"<name> (n of m)".

#### Store a secret:
```bash
# Asks for the value in a masked prompt: the terminal if there is one, otherwise the password box
bwenv set bw://myvault/Work/github/GITHUB_TOKEN

# Several at once; every URI is checked before anything is asked for
bwenv set bw://myvault/Work/myapp/DB_PASSWORD bw://myvault/Work/myapp/API_KEY
```

The value never appears on a command line, in a log or in your shell history, and reaches `bw` on
stdin. `set` writes `bw://` URIs only:

- an existing item has the named field updated (custom field, or `username`/`password` of a login) and
  keeps every other field; a new field is a hidden custom field;
- a missing item is created as a secure note in that folder, and a missing personal folder is created
  (organization collections must already exist);
- for a new item, the last part of the URI is the field and the one before it is the item, so a field
  name containing `/` can only be added to an item that already exists;
- a URI that could mean more than one item is refused, as with `read`. That includes
  `bw://myvault/Work/svc/TOKEN` when there is both a folder `Work` and an item called `Work`; use the
  folder's ID instead of its name to choose.

#### Move a .env file into the vault:
```bash
bwenv import bw://myvault/Work/myapp .env > .env.bwenv
# .env.bwenv now holds KEY=bw://myvault/Work/myapp/KEY for every key. Check it, replace .env with it, and
# load it as before - the references are resolved when the app starts:
mv .env.bwenv .env
set -a; . ./.env; set +a; bwenv run your-app
```

`import` reads `KEY=VALUE` lines (with optional `export`, `#` comments, and `'single'` or
`"double"` quotes), stores each value as a hidden custom field of the item (created if missing), and
prints the references to use instead. Use `-` to read the file from stdin.

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
2. **Locked vault**: The tool will prompt for your master password, once per run
3. **No terminal** (an IDE, a GUI launcher, piped input): bwenv asks in a desktop password box instead —
   `osascript` on macOS, a PowerShell window on Windows, and `kdialog` (KDE) or `zenity` on Linux, falling back
   to Python's `tkinter` if none of those is available. A wrong password is asked for again, up to 3 times.
   With no desktop either (CI, SSH), unlock first with `export BW_SESSION="$(bw unlock --raw)"`
4. **No interaction needed**: Once `BW_SESSION` is set, subsequent runs work seamlessly
5. **Keep the session between runs**: tools that start a new process for every command (agents, IDE tasks)
   would otherwise ask for the password every time. Set `BWENV_SESSION_CACHE` (e.g. `8h`) and bwenv keeps
   the session it unlocks, until then, in:
   - **Linux**: the kernel user keyring (`keyctl`, from `keyutils`), in memory, expired by the kernel;
   - **macOS**: a keychain of its own (`~/Library/Keychains/bwenv.keychain-db`) with a throwaway password,
     locked after the time is up and then deleted;
   - **Windows**: a file encrypted to your account with DPAPI (`%LOCALAPPDATA%\bwenv\session.bin`) that
     records its own expiry.

   An inherited `BW_SESSION` always wins. A cached session that no longer unlocks the vault is discarded and
   you are asked again. `bwenv lock` forgets it at once (`bw lock` also invalidates it, and every other session).

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

Flags can be placed either before or after the subcommand for flexibility. For `run`, they are only read up to the start of your command; use `--` after `run` to make the boundary explicit.

Environment variables:

- `BWENV_TIMEOUT`: Seconds to wait for each Bitwarden CLI call before giving up (default `120`). Without it, an unreachable server (e.g. a dropped VPN) would hang bwenv indefinitely.
- `BWENV_PROMPT`: How to ask for the master password when the vault is locked, and for the values `set` stores: `auto` (default: the terminal if there is one, otherwise a desktop password box), `gui` (always the password box), `tty` (only the terminal) or `none` (never ask; fail unless `BW_SESSION` is set).
- `BWENV_SESSION_CACHE`: How long to keep a session bwenv unlocked, for later runs: e.g. `8h`, `30m`, `90s`, `1d` or a number of seconds. Unset or `0` (the default) keeps nothing. See [Authentication](#authentication).

## Testing

Run the included unit tests:

```bash
python -m unittest test_bwenv -v
```

The tests mock the Bitwarden CLI, so they need neither `bw` nor a vault.

## Security Considerations

- No secret values are logged (not even with `--debug`) or written to disk (except a cached session on
  Windows, encrypted with DPAPI, and only with `BWENV_SESSION_CACHE` set)
- `run` hands the resolved secrets to your command and nothing else: `BW_SESSION`, `BW_PASSWORD`,
  `BW_CLIENTID` and `BW_CLIENTSECRET` are removed from its environment, so it cannot read the rest of your vault
- On Linux and macOS, `run` replaces itself with your command, so no bwenv process stays behind holding secrets
- `send` passes the Send to the Bitwarden CLI on stdin, never on the command line where other users could see it
- A master password typed into the desktop password box goes to `bw unlock` in that process's environment only — never on a command line, in a log, or in the environment of the command `run` starts
- `set` and `import` pass the item to `bw` on stdin; values typed into `set` are never echoed
- A cached session (`BWENV_SESSION_CACHE`) can be read by your other processes until it expires, as an
  exported `BW_SESSION` can; it is never readable by other users, and `run` still removes it from the
  command's environment
- Uses official Bitwarden CLI for all vault operations

## Troubleshooting

### Common Issues

1. **"bw not found"**: Install the Bitwarden CLI
2. **"You are not logged in"**: Run `bw login` first
3. **"Master password required"**: The tool will prompt automatically
4. **"No item found"**: Check your vault name, item name, and field name
5. **"Field not found"**: Verify the field exists in the specified item
6. **"did not finish within 120 seconds"**: The Bitwarden server is unreachable (check your network or VPN), or a very large vault needs a longer `BWENV_TIMEOUT`
7. **"items named ... match" / "items have the URI"**: More than one item fits the reference; add the folder or collection (`bw://`), or keep the `op://` URI on only one item

### Debug Mode

Use `--debug` flag to see detailed operation logs with comprehensive debugging information:

```bash
bwenv --debug read op://vault/item/field
```

Debug output includes:
- **Command parsing**: Arguments, Python version, working directory
- **Environment scanning**: Discovery of op:// URIs in environment variables
- **Bitwarden CLI operations**: Command execution with timing and response details
- **Authentication status**: Vault status and unlock flow
- **Item resolution**: Vault searches, item matching, and field lookups
- **Performance metrics**: Sync timing and operation durations
- **Value handling**: The length of each resolved secret only, never its value

Example debug output:
```
[DEBUG 15:55:14] Debug mode enabled
[DEBUG 15:55:14] Command: run
[DEBUG 15:55:14] Vault status: unlocked
[DEBUG 15:55:14] Found 2 environment variables with supported URIs
[DEBUG 15:55:15] Vault sync completed in 1.70 seconds
[DEBUG 15:55:19] Found matching item: DEMO_DATA (ID: aaaaaaaa-1111-bbbb-2222-cccccccccccc)
[DEBUG 15:55:19] Successfully resolved op:// URI op://Personal/demo/prod/plaintext to value (length: 22 chars)
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
- **v1.9**: Implemented the `send` subcommand to create Bitwarden Sends directly from a URI. It can send a single secret value for field-specific URIs or a JSON object of the entire item for item-only URIs, with an optional `--name flag` for custom titles.
- **v1.10**: Security and correctness release. Secrets no longer leak: `--debug` logs value lengths, never values; `send` no longer logs its payload and passes it to `bw` on stdin instead of the command line; `run` strips `BW_SESSION` and other Bitwarden credentials from the command's environment. Sends now default to one view, hidden text, hidden email and a generic name, with new `--max-access` and `--expire-hours` options, and `op://vault/item` whole-item sends work. Lookups no longer return the wrong secret: `bw://` URIs honour the folder or collection (an unknown one is an error), `op://` matches the exact item rather than any item whose name starts the same, and a reference matching several items is an error. Fixed `op://` finding nothing with current Bitwarden CLIs, whose `--search` no longer matches website URIs. `run -- npm run build` (and `docker`/`cargo`/`kubectl run`) works, and flags after your command are left for it. `run` execs the command on Linux and macOS, so it gets Ctrl-C and SIGTERM and its exit status is bwenv's. Every `bw` call has a timeout (`BWENV_TIMEOUT`), the vault is unlocked at most once and never from piped input, output is decoded as UTF-8, and an npm-installed `bw.cmd` is found on Windows. Item, organization, folder and collection lists are fetched once per run (thanks to @lewis-lees for the item cache). Requires Python 3.7+; tests run on Linux, macOS and Windows.
- **v1.11**: Added a desktop password box for unlocking the vault when there is no terminal (an IDE, a GUI launcher, piped input): `osascript` on macOS, PowerShell on Windows, `kdialog` or `zenity` on Linux, with a `tkinter` fallback. A wrong password is asked for again up to 3 times. `BWENV_PROMPT` (`auto`, `gui`, `tty`, `none`) chooses how bwenv asks.
- **v1.12**: Added `set`, which stores secrets typed into a masked prompt (terminal or password box), and `import`, which moves a `.env` file into hidden fields of one item and prints the references to use instead. Both create a missing item and personal folder, keep the item's other fields, pass values to `bw` on stdin, and refuse a URI that could mean more than one item. Added `BWENV_SESSION_CACHE` to keep an unlocked session between runs for a limited time (kernel keyring on Linux, a self-locking keychain on macOS, a DPAPI-encrypted file on Windows), and `lock` to forget it.
