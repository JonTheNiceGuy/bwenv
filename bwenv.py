#!/usr/bin/env python3
"""
bwenv - Bitwarden Environment Variable Processor

A cross-platform tool to replace environment variables containing Bitwarden secret references
with actual secret values using the Bitwarden CLI.

Usage:
    bwenv run [--no-sync] [--debug] <command> [args...]
    bwenv read [--no-sync] [--debug] <uri>
    bwenv send [--no-sync] [--debug] [--name <title>] [--max-access N] [--expire-hours H] <uri>...
    bwenv set [--no-sync] [--debug] <bw-uri>...
    bwenv import [--no-sync] [--debug] <bw-item-uri> <file>
    bwenv lock

Examples:
    bwenv run sh
    bwenv read op://Employee/example/secret
    bwenv run --no-sync python app.py
    bwenv run -- npm run build
    bwenv send --max-access 3 op://Employee/example/secret
    bwenv set bw://myvault/Work/github/GITHUB_TOKEN
    bwenv import bw://myvault/Work/myapp .env > .env.bwenv

Environment:
    BWENV_TIMEOUT        seconds to wait for each Bitwarden CLI call (default 120)
    BWENV_PROMPT         how to ask for passwords and values: auto (default), gui, tty or none
    BWENV_SESSION_CACHE  keep an unlocked session this long (e.g. 8h); unset or 0: do not keep it
"""

import argparse
import base64
import datetime
import getpass
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
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
PROMPT_MODES = ('auto', 'gui', 'tty', 'none')  # BWENV_PROMPT
MASTER_PASSWORD_ENV = 'BWENV_MASTER_PASSWORD'  # only ever set in bw's own environment
UNLOCK_ATTEMPTS = 3
DIALOG_TIMEOUT = 300  # seconds to wait for someone to answer the password dialog
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


class NoPasswordDialog(Exception):
    """No desktop password dialog is available here"""


def prompt_mode() -> str:
    """How to ask for the master password (BWENV_PROMPT): auto, gui, tty or none"""
    mode = os.environ.get('BWENV_PROMPT', 'auto').strip().lower()
    if mode not in PROMPT_MODES:
        raise BWEnvError(f"BWENV_PROMPT must be one of {', '.join(PROMPT_MODES)}, not '{mode}'")
    return mode


def password_dialog_command(message: str) -> Optional[List[str]]:
    """The command that shows a masked password dialog and prints the answer, or None if there is none.
    
    macOS: osascript. Windows: a PowerShell WinForms box. Linux and other desktops: kdialog on KDE,
    otherwise zenity (or kdialog), and only when there is a display to show it on.
    """
    if sys.platform == 'darwin':
        osascript = shutil.which('osascript')
        if not osascript:
            return None
        text = message.replace('\\', '\\\\').replace('"', '\\"')
        return [osascript, '-e',
                f'text returned of (display dialog "{text}" default answer "" with hidden answer '
                f'with title "bwenv" buttons {{"Cancel", "OK"}} default button "OK" with icon caution)']
    
    if IS_WINDOWS:
        powershell = shutil.which('powershell') or shutil.which('pwsh')
        if not powershell:
            return None
        text = message.replace("'", "''")
        script = (
            "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing;"
            "$f = New-Object Windows.Forms.Form; $f.Text = 'bwenv'; $f.TopMost = $true;"
            "$f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog';"
            "$f.MinimizeBox = $false; $f.MaximizeBox = $false; $f.ClientSize = New-Object Drawing.Size(380, 120);"
            f"$l = New-Object Windows.Forms.Label; $l.Text = '{text}'; $l.SetBounds(12, 12, 356, 32);"
            "$t = New-Object Windows.Forms.TextBox; $t.UseSystemPasswordChar = $true; $t.SetBounds(12, 48, 356, 24);"
            "$ok = New-Object Windows.Forms.Button; $ok.Text = 'OK'; $ok.DialogResult = 'OK'; $ok.SetBounds(212, 84, 75, 25);"
            "$no = New-Object Windows.Forms.Button; $no.Text = 'Cancel'; $no.DialogResult = 'Cancel'; $no.SetBounds(293, 84, 75, 25);"
            "$f.Controls.AddRange(@($l, $t, $ok, $no)); $f.AcceptButton = $ok; $f.CancelButton = $no;"
            "$f.Add_Shown({ $f.Activate(); $t.Focus() });"
            "if ($f.ShowDialog() -ne 'OK') { exit 1 };"
            "[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false; [Console]::Out.Write($t.Text)"
        )
        return [powershell, '-NoProfile', '-NonInteractive', '-STA', '-Command', script]
    
    if not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
        return None
    tools = ('kdialog', 'zenity') if 'KDE' in os.environ.get('XDG_CURRENT_DESKTOP', '').upper() else ('zenity', 'kdialog')
    for tool in tools:
        path = shutil.which(tool)
        if path and tool == 'kdialog':
            return [path, '--title', 'bwenv', '--password', message]
        if path:
            return [path, '--entry', '--hide-text', '--title', 'bwenv', '--text', message]
    return None


def _ask_password_with_tkinter(message: str) -> Optional[str]:
    """Fallback dialog using tkinter, which some Python builds include. Raises NoPasswordDialog if unusable."""
    try:
        import tkinter
        from tkinter import simpledialog
    except ImportError:
        raise NoPasswordDialog()
    try:
        root = tkinter.Tk()
    except tkinter.TclError:  # no display
        raise NoPasswordDialog()
    try:
        root.withdraw()
        return simpledialog.askstring('bwenv', message, show='*', parent=root)
    finally:
        root.destroy()


def ask_password_in_dialog(message: str) -> Optional[str]:
    """Ask for the master password in a desktop dialog.
    
    Returns the password, or None if the dialog was cancelled. Raises NoPasswordDialog if no dialog
    can be shown. The password only travels through this process's pipe from the dialog; it is
    never logged or put on a command line.
    """
    command = password_dialog_command(message)
    if command is None:
        return _ask_password_with_tkinter(message)
    
    logging.debug(f"Asking for a password with {os.path.basename(command[0])}")
    try:
        result = subprocess.run(command, capture_output=True, encoding='utf-8', timeout=DIALOG_TIMEOUT)
    except FileNotFoundError:
        raise NoPasswordDialog()
    except subprocess.TimeoutExpired:
        return None  # nobody answered: treat as cancelled
    if result.returncode != 0:
        return None
    return (result.stdout or '').lstrip('\ufeff').rstrip('\r\n')


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


def ask_secret_value(message: str) -> str:
    """Ask for a secret to store, masked: on the terminal if there is one, otherwise in the password dialog.

    Follows BWENV_PROMPT like the master password prompt. The value is never echoed, logged or put on
    a command line. Raises BWEnvError if nobody can be asked, the prompt is cancelled or the value is empty.
    """
    mode = prompt_mode()
    if mode == 'tty' or (mode == 'auto' and sys.stdin.isatty()):
        if not sys.stdin.isatty():
            raise BWEnvError("BWENV_PROMPT=tty but there is no terminal to ask for the value on")
        try:
            value = getpass.getpass(message + ' ')
        except (EOFError, KeyboardInterrupt):
            value = None
    elif mode == 'none':
        raise BWEnvError("BWENV_PROMPT=none, so bwenv cannot ask for the value to store")
    else:
        try:
            value = ask_password_in_dialog(message)
        except NoPasswordDialog:
            raise BWEnvError("bwenv cannot ask for the value here (no terminal or password dialog)")
    if value is None:
        raise BWEnvError("Cancelled; nothing was stored")
    if not value:
        raise BWEnvError("The value was empty; nothing was stored")
    return value


SESSION_CACHE_ENV = 'BWENV_SESSION_CACHE'
DURATION_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}


def session_cache_seconds() -> int:
    """How long to keep an unlocked session (BWENV_SESSION_CACHE, e.g. 8h, 30m, 3600); 0 means no cache"""
    value = os.environ.get(SESSION_CACHE_ENV, '').strip().lower()
    if not value:
        return 0
    match = re.fullmatch(r'(\d+(?:\.\d+)?)\s*([smhd]?)', value)
    if not match:
        raise BWEnvError(f"{SESSION_CACHE_ENV} must be a duration such as 8h, 30m or 3600 (seconds), not '{value}'")
    return int(float(match.group(1)) * DURATION_UNITS[match.group(2) or 's'])


class SessionCache:
    """Somewhere to keep an unlocked vault session between runs, until it expires.

    The session is passed to the store on stdin or in memory, never on a command line or in a log.
    """
    name = 'session cache'

    def load(self) -> Optional[str]:
        """The cached session, or None if there is none or it has expired"""
        raise NotImplementedError

    def store(self, session: str, seconds: int):
        """Keep the session for this many seconds, replacing any cached one"""
        raise NotImplementedError

    def clear(self):
        """Forget the cached session now"""
        raise NotImplementedError

    @staticmethod
    def _run(command: List[str], input_text: Optional[str] = None) -> subprocess.CompletedProcess:
        return subprocess.run(command, input=input_text, capture_output=True, encoding='utf-8', timeout=30)


class KeyctlSessionCache(SessionCache):
    """Linux: the kernel user keyring, held in memory, with an expiry the kernel enforces"""
    name = 'kernel keyring (keyctl)'

    def __init__(self, keyctl: str, description: str = 'bwenv_session'):
        self.keyctl = keyctl
        self.description = description

    def _key_id(self) -> Optional[str]:
        result = self._run([self.keyctl, 'search', '@u', 'user', self.description])
        return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None

    def load(self) -> Optional[str]:
        key_id = self._key_id()  # an expired key is not found
        if not key_id:
            return None
        result = self._run([self.keyctl, 'pipe', key_id])
        return result.stdout if result.returncode == 0 and result.stdout else None

    def store(self, session: str, seconds: int):
        self.clear()
        result = self._run([self.keyctl, 'padd', 'user', self.description, '@u'], input_text=session)
        key_id = result.stdout.strip()
        if result.returncode != 0 or not key_id:
            raise BWEnvError(f"keyctl padd failed: {result.stderr.strip() or f'exit code {result.returncode}'}")
        # Readable by the user's other processes (not only this one, the "possessor"), and nobody else's
        for args in (['setperm', key_id, '0x3f3f0000'], ['timeout', key_id, str(seconds)]):
            if self._run([self.keyctl] + args).returncode != 0:
                self.clear()
                raise BWEnvError(f"keyctl {args[0]} failed")

    def clear(self):
        for _ in range(10):  # normally one key; stop rather than loop forever on an odd keyring
            key_id = self._key_id()
            if not key_id or self._run([self.keyctl, 'unlink', key_id, '@u']).returncode != 0:
                return


class KeychainSessionCache(SessionCache):
    """macOS: a keychain of bwenv's own, with a throwaway password, that locks itself after the expiry.

    Nothing ever unlocks it again: once it has locked, or a small file beside it says the time is up,
    the keychain is deleted and the next unlock makes a new one.
    """
    name = 'bwenv keychain'
    SERVICE = 'bwenv'
    ACCOUNT = 'bw-session'

    def __init__(self, security: str, keychain: Optional[str] = None):
        self.security = security
        self.keychain = keychain or os.path.expanduser('~/Library/Keychains/bwenv.keychain-db')
        self.expiry_file = self.keychain + '.expires'

    def _expires(self) -> float:
        try:
            with open(self.expiry_file, encoding='utf-8') as f:
                return float(f.read().strip())
        except (OSError, ValueError):
            return 0.0

    def load(self) -> Optional[str]:
        if not os.path.exists(self.keychain):
            return None
        if time.time() >= self._expires():
            self.clear()  # never read an expired keychain: it may be locked, and reading would ask to unlock it
            return None
        result = self._run([self.security, 'find-generic-password', '-s', self.SERVICE, '-a', self.ACCOUNT,
                            '-w', self.keychain])
        session = result.stdout.strip()
        return session if result.returncode == 0 and session else None

    def store(self, session: str, seconds: int):
        self.clear()
        if '"' in self.keychain or not re.fullmatch(r'[A-Za-z0-9+/=._-]+', session):
            raise BWEnvError("cannot pass this session or keychain path to `security -i` safely")
        # `security -i` reads the commands on stdin, so neither the session nor the keychain password is on argv
        commands = (
            f'create-keychain -p {secrets.token_hex(32)} "{self.keychain}"\n'
            f'set-keychain-settings -u -t {seconds} "{self.keychain}"\n'
            f'add-generic-password -U -s {self.SERVICE} -a {self.ACCOUNT} -w {session} "{self.keychain}"\n'
        )
        result = self._run([self.security, '-i'], input_text=commands)
        if result.returncode != 0 or self.load_unchecked() != session:
            self.clear()
            raise BWEnvError("could not store the session in a keychain")
        with open(self.expiry_file, 'w', encoding='utf-8') as f:
            f.write(f"{time.time() + seconds:.0f}\n")

    def load_unchecked(self) -> Optional[str]:
        result = self._run([self.security, 'find-generic-password', '-s', self.SERVICE, '-a', self.ACCOUNT,
                            '-w', self.keychain])
        return result.stdout.strip() if result.returncode == 0 else None

    def clear(self):
        if os.path.exists(self.keychain):
            self._run([self.security, 'delete-keychain', self.keychain])
        for path in (self.keychain, self.expiry_file):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass


class DpapiSessionCache(SessionCache):
    """Windows: a file encrypted to the user's account with DPAPI, carrying its own expiry time.

    Unlike a session credential in Credential Manager, this works for every logon type (including
    SSH and WinRM), and bwenv enforces the expiry when it reads the file.
    """
    name = 'DPAPI-encrypted file'
    ENTROPY = b'bwenv-session'

    def __init__(self, path: Optional[str] = None):
        base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
        self.path = path or os.path.join(base, 'bwenv', 'session.bin')

    def load(self) -> Optional[str]:
        try:
            with open(self.path, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            return None
        session = ''
        try:
            expires, _, session =dpapi_unprotect(data, self.ENTROPY).decode('utf-8').partition('\n')
            expired = time.time() >= float(expires)
        except (OSError, ValueError, UnicodeDecodeError):
            expired = True  # unreadable: treat as expired
        if expired or not session:
            self.clear()
            return None
        return session

    def store(self, session: str, seconds: int):
        data = dpapi_protect(f"{time.time() + seconds:.0f}\n{session}".encode('utf-8'), self.ENTROPY)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        temp = self.path + '.tmp'
        with open(temp, 'wb') as f:
            f.write(data)
        os.replace(temp, self.path)

    def clear(self):
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass


def _dpapi(data: bytes, entropy: bytes, protect: bool) -> bytes:
    """CryptProtectData / CryptUnprotectData for the current user, without any UI"""
    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]

    def blob(raw: bytes) -> DataBlob:
        buffer = ctypes.create_string_buffer(raw, len(raw))
        return DataBlob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    function.argtypes = [ctypes.POINTER(DataBlob), wintypes.LPCWSTR, ctypes.POINTER(DataBlob), ctypes.c_void_p,
                         ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob)]
    function.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    data_in, entropy_in, data_out = blob(data), blob(entropy), DataBlob()
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    if not function(ctypes.byref(data_in), 'bwenv' if protect else None, ctypes.byref(entropy_in), None, None,
                    CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(data_out)):
        raise OSError(f"DPAPI failed (error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(data_out.pbData, ctypes.c_void_p))


def dpapi_protect(data: bytes, entropy: bytes) -> bytes:
    return _dpapi(data, entropy, protect=True)


def dpapi_unprotect(data: bytes, entropy: bytes) -> bytes:
    return _dpapi(data, entropy, protect=False)


def default_session_cache() -> Optional[SessionCache]:
    """This platform's session store, or None if it has none (Linux needs keyctl, from keyutils)"""
    if IS_WINDOWS:
        return DpapiSessionCache()
    if sys.platform == 'darwin':
        security = shutil.which('security')
        return KeychainSessionCache(security) if security else None
    keyctl = shutil.which('keyctl')
    return KeyctlSessionCache(keyctl) if keyctl else None


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


class WriteTarget:
    """Where `set` or `import` stores a value: an existing item, or the item to create"""

    def __init__(self, org_id: Optional[str], path: str, item_name: str, field: str, item: Optional[Dict]):
        self.org_id = org_id
        self.path = path  # folder (personal vault) or collection (organization); '' for none
        self.item_name = item_name
        self.field = field
        self.item = item  # None until the item exists

    @property
    def key(self) -> tuple:
        """The same for every target in one item, so writes to it can be grouped"""
        return ('id', self.item['id']) if self.item else ('new', self.org_id, self.path, self.item_name)


ENV_LINE_PATTERN = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$')
DOUBLE_QUOTE_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\', '$': '$', '`': '`'}


def parse_env_file(text: str) -> Dict[str, str]:
    """Read KEY=VALUE lines, as a .env file or a shell script of exports would set them.

    Blank lines and # comments are skipped, `export ` is allowed, 'single' quotes are literal and
    "double" quotes understand backslash escapes. Errors name the line number, never its contents.
    """
    values = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.strip().startswith('#'):
            continue
        match = ENV_LINE_PATTERN.match(line)
        if not match:
            raise BWEnvError(f"Line {number} is not KEY=VALUE")
        key, raw = match.groups()
        values[key] = _env_value(raw, number)
    return values


def _env_value(raw: str, number: int) -> str:
    """The value of one KEY=VALUE line, after quotes, escapes and any trailing comment"""
    if raw[:1] not in ('"', "'"):
        return re.split(r'\s+#', raw, maxsplit=1)[0].strip()

    quote, value, i = raw[0], [], 1
    while i < len(raw) and raw[i] != quote:
        if quote == '"' and raw[i] == '\\' and i + 1 < len(raw):
            i += 1
            value.append(DOUBLE_QUOTE_ESCAPES.get(raw[i], '\\' + raw[i]))
        else:
            value.append(raw[i])
        i += 1
    rest = raw[i + 1:].strip()
    if i >= len(raw):
        raise BWEnvError(f"Line {number} has an unterminated quote (values over several lines are not supported)")
    if rest and not rest.startswith('#'):
        raise BWEnvError(f"Line {number} has text after its closing quote")
    return ''.join(value)


class BitwardenClient:
    """Client for interacting with Bitwarden CLI"""
    
    # Commands that need an unlocked vault
    AUTH_COMMANDS = ('sync', 'list', 'get', 'send', 'create', 'edit')

    def __init__(self, no_sync: bool = False, session_cache: Optional[SessionCache] = None):
        self.sync = not no_sync
        self._session = os.environ.get('BW_SESSION')
        self._session_checked = False
        self._session_cache = session_cache  # None: the platform's own, if BWENV_SESSION_CACHE is set
        self._session_from_cache = False
        self._session_cache_missing = False
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
                 interactive: bool = False, extra_env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        """Run bw and return the completed process. Only the subcommand is logged, never the arguments."""
        command = [resolve_executable('bw')] + args
        logging.debug(f"Running Bitwarden CLI command: bw {' '.join(args[:2])}")
        env = self._bw_env()
        env.update(extra_env or {})
        try:
            if interactive:
                # The master password prompt needs the terminal: inherit stdin and stderr, capture the token.
                return subprocess.run(command, stdout=subprocess.PIPE, encoding='utf-8', env=env)
            timeout = bw_timeout()
            return subprocess.run(command, input=input_text, capture_output=True, encoding='utf-8',
                                  env=env, timeout=timeout)
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

        cache_seconds = session_cache_seconds()
        if not self._session and cache_seconds:
            self._load_cached_session()

        result = self._exec_bw(['status'])
        try:
            status = json.loads(result.stdout).get('status')
        except (json.JSONDecodeError, TypeError, AttributeError):
            status = None
        logging.debug(f"Vault status: {status}")

        if self._session_from_cache and status in ('locked', 'unauthenticated'):
            logging.debug("The cached session no longer unlocks the vault; forgetting it")
            self._forget_cached_session()
            self._session = None
        if status == 'unauthenticated':
            raise BWEnvError("You are not logged in to Bitwarden. Run `bw login` first.")
        if status == 'locked':
            self._unlock()
            if cache_seconds:
                self._cache_session(cache_seconds)
        # 'unlocked', or a status we cannot read: let the command itself report any problem
        self._session_checked = True

    def _get_session_cache(self) -> Optional[SessionCache]:
        if self._session_cache is None and not self._session_cache_missing:
            self._session_cache = default_session_cache()
            if self._session_cache is None:
                print(f"Warning: {SESSION_CACHE_ENV} is set, but there is no session store here "
                      f"(on Linux, install keyctl from keyutils)", file=sys.stderr)
                self._session_cache_missing = True  # warn once
        return self._session_cache

    def _load_cached_session(self):
        """Use a cached, unexpired session from an earlier run, if there is one"""
        cache = self._get_session_cache()
        if not cache:
            return
        try:
            session = cache.load()
        except (OSError, subprocess.SubprocessError, BWEnvError) as e:
            logging.debug(f"Could not read the {cache.name}: {e}")
            return
        if session:
            logging.debug(f"Using the session cached in the {cache.name}")
            self._session = session
            self._session_from_cache = True
        else:
            logging.debug(f"No unexpired session in the {cache.name}")

    def _cache_session(self, seconds: int):
        """Keep the session this client unlocked for later runs. A failure only costs a password prompt later."""
        cache = self._get_session_cache()
        if not cache or not self._session:
            return
        try:
            cache.store(self._session, seconds)
            logging.debug(f"Cached the session in the {cache.name} for {seconds} seconds")
        except (OSError, subprocess.SubprocessError, BWEnvError) as e:
            print(f"Warning: could not cache the Bitwarden session in the {cache.name}: {e}", file=sys.stderr)

    def _forget_cached_session(self):
        cache = self._get_session_cache()
        if cache:
            try:
                cache.clear()
            except (OSError, subprocess.SubprocessError) as e:
                logging.debug(f"Could not clear the {cache.name}: {e}")
        self._session_from_cache = False

    def _unlock(self):
        """Ask for the master password and keep the session for this client.
        
        On a terminal bw asks itself; without one (an IDE, CI, a GUI launcher, piped stdin) bwenv shows a
        desktop password dialog. BWENV_PROMPT=gui|tty|none forces a choice.
        """
        mode = prompt_mode()
        if mode == 'tty' or (mode == 'auto' and sys.stdin.isatty()):
            if sys.stdin.isatty():
                self._unlock_on_terminal()
                return
        elif mode != 'none' and self._unlock_with_dialog():
            return
        
        raise BWEnvError("The Bitwarden vault is locked and bwenv cannot ask for the master password here "
                         "(no terminal or password dialog). Unlock it first, e.g. "
                         "export BW_SESSION=\"$(bw unlock --raw)\"")
    
    def _unlock_on_terminal(self):
        """Let bw ask for the master password on the terminal"""
        print("Bitwarden vault is locked. Please enter your master password to unlock:", file=sys.stderr)
        result = self._exec_bw(['unlock', '--raw'], interactive=True)
        session = (result.stdout or '').strip()
        if result.returncode != 0 or not session:
            raise BWEnvError(f"Failed to unlock the Bitwarden vault (bw unlock exited {result.returncode})")
        self._session = session
        logging.debug("Vault unlocked")
    
    def _unlock_with_dialog(self) -> bool:
        """Unlock with a password typed into a desktop dialog. Returns False if no dialog is available."""
        message = "Bitwarden master password (to unlock your vault for bwenv):"
        for _ in range(UNLOCK_ATTEMPTS):
            try:
                password = ask_password_in_dialog(message)
            except NoPasswordDialog:
                return False
            if password is None:
                raise BWEnvError("Unlocking the Bitwarden vault was cancelled")
            
            # The password reaches bw in its own environment only - never argv, logs or os.environ
            result = self._exec_bw(['unlock', '--passwordenv', MASTER_PASSWORD_ENV, '--raw', '--nointeraction'],
                                   extra_env={MASTER_PASSWORD_ENV: password})
            del password
            session = (result.stdout or '').strip()
            if result.returncode == 0 and session:
                self._session = session
                logging.debug("Vault unlocked")
                return True
            
            stderr = result.stderr.strip() if isinstance(result.stderr, str) else ''
            if 'invalid master password' not in stderr.lower():
                raise BWEnvError(f"Failed to unlock the Bitwarden vault: {stderr or f'exit code {result.returncode}'}")
            message = "Incorrect master password, please try again:"
        
        raise BWEnvError(f"Failed to unlock the Bitwarden vault after {UNLOCK_ATTEMPTS} attempts")
    
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

    def _split_write_uri(self, uri: str, min_parts: int) -> Tuple[Optional[str], List[str]]:
        """Split a bw:// URI to write to into (organization ID or None, the parts after the vault)"""
        if not uri.startswith('bw://'):
            raise BWEnvError(f"bwenv can only store secrets at bw:// URIs, not {uri}")
        parts = uri[5:].rstrip('/').split('/')
        if len(parts) < min_parts + 1 or not all(parts):
            raise BWEnvError(f"Invalid bw:// URI to store at: {uri}")
        return self._resolve_organization(parts[0]), parts[1:]

    def _items_named(self, org_id: Optional[str], path: str, name: str) -> List[Dict]:
        """Items in this vault called `name`, in the folder/collection `path` if one is given"""
        matches = [item for item in self._get_all_items()
                   if item.get('organizationId') == org_id and item.get('name') == name]
        if path:
            container_ids = self._resolve_path_ids(org_id, path)
            matches = [item for item in matches if self._item_in_containers(item, org_id, container_ids)]
        return matches

    def plan_field_write(self, uri: str) -> 'WriteTarget':
        """Work out which item, and which field, a bw://vault/[folder/]item/FIELD URI writes to.

        An existing item is preferred, matched like `read` does, except the field need not exist yet:
        a split where the item already has the field wins; otherwise exactly one split may match an item.
        With no matching item, a new one is named by the last-but-one part, and the field by the last.
        """
        org_id, parts = self._split_write_uri(uri, min_parts=2)
        found = []
        for split_point in range(1, len(parts)):
            path, name, field = '/'.join(parts[:split_point - 1]), parts[split_point - 1], '/'.join(parts[split_point:])
            matches = self._items_named(org_id, path, name)
            if len(matches) > 1:
                where = f"'{path}'" if path else "this vault"
                raise BWEnvError(f"{len(matches)} items named '{name}' match in {where}; "
                                 f"add the folder or collection to the URI to choose one")
            if matches:
                found.append(WriteTarget(org_id, path, name, field, matches[0]))

        with_field = [t for t in found if self.get_field_value(t.item, t.field) is not None]
        if len(with_field) == 1:
            return with_field[0]

        # A field that does not exist yet: the item/FIELD reading (last-but-one part, last part) must be the only one
        new = WriteTarget(org_id, '/'.join(parts[:-2]), parts[-2], parts[-1], None)
        if len(found) == 1 and (found[0].path, found[0].item_name) == (new.path, new.item_name):
            return found[0]
        if with_field or found:
            meanings = [f"field '{t.field}' of '{t.item_name}'" for t in (with_field or found)]
            if not with_field and not any(t.item_name == new.item_name and t.path == new.path for t in found):
                meanings.append(f"a new item '{new.item_name}'" + (f" in '{new.path}'" if new.path else ''))
            raise BWEnvError(f"{uri} could mean more than one item: {'; or '.join(meanings)}. "
                             f"Use the folder or collection ID in the URI to choose one")
        return new

    def plan_item_write(self, uri: str) -> 'WriteTarget':
        """The item a bw://vault/[folder/]item URI writes to: an existing one, or a new one to create"""
        org_id, parts = self._split_write_uri(uri, min_parts=1)
        path, name = '/'.join(parts[:-1]), parts[-1]
        matches = self._items_named(org_id, path, name)
        if len(matches) > 1:
            where = f"'{path}'" if path else "this vault"
            raise BWEnvError(f"{len(matches)} items named '{name}' match in {where}; "
                             f"add the folder or collection to the URI to choose one")
        return WriteTarget(org_id, path, name, '', matches[0] if matches else None)

    def write_fields(self, target: 'WriteTarget', values: Dict[str, str]) -> Dict:
        """Store the values in the target item, creating it (and its folder) if it does not exist yet.

        Named fields are updated and every other field is kept; new fields are hidden custom fields.
        The item reaches bw on stdin, never in argv or logs. The cache is updated, so a later read in
        the same run sees the new values.
        """
        if target.item is None:
            item = self._create_item(target, values)
        else:
            item = self._update_item(target.item['id'], values)
        self._remember_item(item)
        target.item = item
        return item

    def _container_for_write(self, org_id: Optional[str], path: str) -> Optional[str]:
        """The ID of the folder (personal vault) or collection (organization) to create an item in"""
        if org_id is not None and not path:
            raise BWEnvError("An organization item needs a collection: bw://Org/Collection/item/FIELD")
        if not path:
            return None
        ids = self._resolve_path_ids(org_id, path)
        if len(ids) > 1:
            raise BWEnvError(f"{len(ids)} folders or collections are called '{path}'; use its ID in the URI")
        if ids:
            return ids.pop()
        if org_id is not None:
            raise BWEnvError(f"Collection '{path}' not found; bwenv does not create collections, so create it "
                             f"in Bitwarden first")

        logging.debug(f"Creating folder '{path}'")
        folder = json.loads(self._run_bw_command(['create', 'folder'], input_text=self._encode({'name': path})))
        self._folders_cache = None
        return folder['id']

    def _create_item(self, target: 'WriteTarget', values: Dict[str, str]) -> Dict:
        """Create a secure note holding the values as hidden custom fields"""
        container_id = self._container_for_write(target.org_id, target.path)
        logging.debug(f"Creating item '{target.item_name}' with {len(values)} field(s)")
        item = {
            "organizationId": target.org_id,
            "collectionIds": [container_id] if target.org_id else None,
            "folderId": None if target.org_id else container_id,
            "type": 2,  # Secure note
            "name": target.item_name,
            "notes": None,
            "favorite": False,
            "fields": [{"name": name, "value": value, "type": 1, "linkedId": None} for name, value in values.items()],
            "secureNote": {"type": 0},
            "reprompt": 0,
        }
        return json.loads(self._run_bw_command(['create', 'item'], input_text=self._encode(item)))

    def _update_item(self, item_id: str, values: Dict[str, str]) -> Dict:
        """Set the named fields of an existing item, keeping the others"""
        item = json.loads(self._run_bw_command(['get', 'item', item_id]))  # the current version, not the cached one
        logging.debug(f"Updating {len(values)} field(s) in item '{item.get('name')}'")
        fields = item.get('fields') or []
        for name, value in values.items():
            field = next((f for f in fields if f.get('name') == name), None)
            if field is not None:
                field['value'] = value
            elif name in ('username', 'password') and item.get('login') is not None:
                item['login'][name] = value
            else:
                fields.append({"name": name, "value": value, "type": 1, "linkedId": None})
        item['fields'] = fields
        return json.loads(self._run_bw_command(['edit', 'item', item_id], input_text=self._encode(item)))

    def _remember_item(self, item: Dict):
        """Put a created or edited item into the cache in place of the old copy"""
        if self._items_cache is not None:
            self._items_cache = [i for i in self._items_cache if i.get('id') != item.get('id')] + [item]
        self._op_items_cache = None

    @staticmethod
    def _encode(data: Dict) -> str:
        """Equivalent to `bw encode`, without an extra bw process"""
        return base64.b64encode(json.dumps(data).encode('utf-8')).decode('ascii')

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


def set_secrets(args: argparse.Namespace):
    """Ask for a value for each bw:// URI, masked, and store it"""
    bw_client = BitwardenClient(no_sync=args.no_sync)
    try:
        # Check every URI before asking for anything, so a typo does not waste the values typed so far
        targets = [bw_client.plan_field_write(uri) for uri in args.uri]
        groups: Dict[tuple, List[WriteTarget]] = {}
        for target in targets:
            groups.setdefault(target.key, []).append(target)
        for group in groups.values():
            names = [t.field for t in group]
            if len(set(names)) < len(names):
                raise BWEnvError(f"The same field is named twice for item '{group[0].item_name}'")

        for group in groups.values():
            values = {}
            for target in group:
                state = 'replace' if target.item and bw_client.get_field_value(target.item, target.field) is not None else 'new'
                values[target.field] = ask_secret_value(f"Value for {target.field} in {target.item_name} ({state}):")
            bw_client.write_fields(group[0], values)
            del values
            for target in group:
                print(f"Stored {target.field} in '{target.item_name}'", file=sys.stderr)
    except BWEnvError as e:
        logging.debug(f"Failed to store secret: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def import_env_file(args: argparse.Namespace):
    """Copy the values of a KEY=VALUE file into hidden fields of one item, and print the references to use instead"""
    bw_client = BitwardenClient(no_sync=args.no_sync)
    try:
        try:
            if args.file == '-':
                text = sys.stdin.read()
            else:
                with open(args.file, encoding='utf-8-sig') as f:
                    text = f.read()
        except OSError as e:
            raise BWEnvError(f"Cannot read {args.file}: {e.strerror}")
        values = parse_env_file(text)
        del text
        if not values:
            raise BWEnvError(f"No KEY=VALUE lines in {args.file}")

        target = bw_client.plan_item_write(args.uri)
        bw_client.write_fields(target, values)
        print(f"Stored {len(values)} field(s) in '{target.item_name}'", file=sys.stderr)
        base = args.uri.rstrip('/')
        for key in values:
            print(f"{key}={base}/{key}")
    except BWEnvError as e:
        logging.debug(f"Failed to import: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def lock_session(args: argparse.Namespace):
    """Forget the session cached by BWENV_SESSION_CACHE"""
    cache = default_session_cache()
    if cache is None:
        print("There is no session store on this system, so nothing is cached", file=sys.stderr)
        return
    try:
        cache.clear()
    except (OSError, subprocess.SubprocessError) as e:
        print(f"Error: could not clear the {cache.name}: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Forgot the cached Bitwarden session ({cache.name})", file=sys.stderr)


BWENV_FLAGS = ('--debug', '--no-sync')
SUBCOMMANDS = ('run', 'read', 'send', 'set', 'import', 'lock')


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

    set_parser = subparsers.add_parser('set', help='Store secrets, asking for each value in a masked prompt')
    set_parser.add_argument('uri', nargs='+',
                            help='bw:// URI(s) of the field(s) to store (e.g., bw://myvault/Folder/item/API_TOKEN)')

    import_parser = subparsers.add_parser('import', help='Copy the values of a KEY=VALUE file into an item')
    import_parser.add_argument('uri', help='bw:// URI of the item to store them in (e.g., bw://myvault/Folder/item)')
    import_parser.add_argument('file', help="KEY=VALUE file to read, or '-' for stdin")

    subparsers.add_parser('lock', help=f'Forget the session cached by {SESSION_CACHE_ENV}')
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
    elif args.command == 'set':
        set_secrets(args)
    elif args.command == 'import':
        import_env_file(args)
    elif args.command == 'lock':
        lock_session(args)


if __name__ == '__main__':
    main()