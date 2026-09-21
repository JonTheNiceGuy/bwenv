#!/usr/bin/env python3
"""Contract tests for the Vaultwarden-compatible op:// resolver."""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import bwenv


class FakeBW:
    def __init__(self, organizations, items):
        self.organizations = organizations
        self.items = items
        self.calls = []

    def __call__(self, args, env):
        self.calls.append((args, env.copy()))
        if args == ["status"]:
            return '{"status":"unlocked"}'
        if args == ["sync"]:
            return ""
        if args == ["list", "organizations"]:
            return bwenv.json.dumps(self.organizations)
        if args == ["list", "items"]:
            return bwenv.json.dumps(self.items)
        raise AssertionError(f"unexpected bw command: {args}")


def item(name, organization_id, fields=None, username=None, password=None, uris=None):
    return {
        "name": name,
        "organizationId": organization_id,
        "fields": fields or [],
        "login": {"username": username, "password": password, "uris": uris or []},
        "notes": "notes-value",
    }


class VaultResolverTests(unittest.TestCase):
    def setUp(self):
        self.orgs = [{"id": "infra-id", "name": "Infra"}]
        self.items = [
            item(
                "service",
                "infra-id",
                fields=[{"name": "token", "value": "custom-token"}],
                username="login-user",
                password="login-password",
            )
        ]

    def resolver(self, organizations=None, items=None):
        return bwenv.VaultResolver(
            runner=FakeBW(organizations or self.orgs, items or self.items), sync=False
        )

    def test_direct_lookup_prefers_custom_fields(self):
        self.assertEqual(
            "custom-token", self.resolver().resolve("op://Infra/service/token")
        )

    def test_direct_lookup_supports_standard_login_and_notes_fields(self):
        resolver = self.resolver()
        self.assertEqual("login-user", resolver.resolve("op://Infra/service/username"))
        self.assertEqual("login-password", resolver.resolve("op://Infra/service/password"))
        self.assertEqual("notes-value", resolver.resolve("op://Infra/service/notes"))

    def test_uri_metadata_is_a_fallback_only(self):
        resolver = self.resolver(
            organizations=[],
            items=[
                item(
                    "renamed-item",
                    "other-org",
                    fields=[{"name": "token", "value": "fallback-token"}],
                    uris=[{"uri": "op://Infra/service"}],
                )
            ],
        )
        self.assertEqual("fallback-token", resolver.resolve("op://Infra/service/token"))

    def test_ambiguous_item_fails_closed(self):
        duplicate = item("service", "infra-id", fields=[{"name": "token", "value": "other"}])
        with self.assertRaisesRegex(bwenv.ResolutionError, "ambiguous"):
            self.resolver(items=self.items + [duplicate]).resolve("op://Infra/service/token")

    def test_missing_field_does_not_expose_a_secret(self):
        with self.assertRaisesRegex(bwenv.ResolutionError, "op://Infra/service/missing") as raised:
            self.resolver().resolve("op://Infra/service/missing")
        self.assertNotIn("custom-token", str(raised.exception))

    def test_simple_bw_uri_remains_supported(self):
        self.assertEqual(
            "custom-token", self.resolver().resolve("bw://Infra/service/token")
        )

    def test_bw_uri_supports_standard_login_and_notes_fields(self):
        resolver = self.resolver()
        self.assertEqual("login-user", resolver.resolve("bw://Infra/service/username"))
        self.assertEqual("login-password", resolver.resolve("bw://Infra/service/password"))
        self.assertEqual("notes-value", resolver.resolve("bw://Infra/service/notes"))

    def test_bw_uri_uri_metadata_is_a_fallback_only(self):
        resolver = self.resolver(
            organizations=[],
            items=[
                item(
                    "renamed-item",
                    "other-org",
                    fields=[{"name": "token", "value": "fallback-token"}],
                    uris=[{"uri": "op://Infra/service"}],
                )
            ],
        )
        self.assertEqual("fallback-token", resolver.resolve("bw://Infra/service/token"))

    def test_bw_uri_rejects_references_op_uri_would_reject(self):
        resolver = self.resolver()
        for invalid in ("bw://Infra/service", "bw://Infra", "bw:///service/token"):
            with self.subTest(uri=invalid):
                with self.assertRaises(bwenv.ResolutionError):
                    resolver.resolve(invalid)

    def test_bw_uri_parses_exactly_like_op_uri(self):
        for uri in (
            "bw://Infra/service/token",
            "bw://Infra/service/nested/field",
            "bw://Infra/service.user/token",
        ):
            with self.subTest(uri=uri):
                self.assertIsNotNone(bwenv.URIParser.parse_bw_uri(uri))
                expected = bwenv.URIParser.parse_op_uri("op://" + uri.removeprefix("bw://"))
                self.assertIsNotNone(expected)

    def test_missing_bw_fails_without_raw_process_details(self):
        with patch.object(bwenv.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(bwenv.BWEnvError, "was not found") as raised:
                bwenv.VaultResolver(runner=bwenv._default_bw_runner, sync=False).resolve(
                    "op://Infra/service/token"
                )
        self.assertNotIn("FileNotFoundError", str(raised.exception))

    def test_bw_stderr_is_not_relayed_in_diagnostics(self):
        result = type("Result", (), {"returncode": 23, "stdout": "", "stderr": "RAW_VALUE"})()
        with patch.object(bwenv.subprocess, "run", return_value=result):
            with self.assertRaises(bwenv.BWEnvError) as raised:
                bwenv._default_bw_runner(["status"], {})
        self.assertNotIn("RAW_VALUE", str(raised.exception))

    def test_locked_session_and_sync_failure_fail_closed(self):
        def locked(args, env):
            return '{"status":"locked"}' if args == ["status"] else ""

        with self.assertRaisesRegex(bwenv.BWEnvError, "not unlocked"):
            bwenv.VaultResolver(runner=locked, sync=False).resolve("op://Infra/service/token")

        def sync_failure(args, env):
            if args == ["status"]:
                return '{"status":"unlocked"}'
            if args == ["sync"]:
                raise bwenv.BWEnvError("Bitwarden command failed: sync")
            raise AssertionError(args)

        with self.assertRaisesRegex(bwenv.BWEnvError, "sync"):
            bwenv.VaultResolver(runner=sync_failure, sync=True).resolve("op://Infra/service/token")


class InjectTests(unittest.TestCase):
    def setUp(self):
        self.resolver = bwenv.VaultResolver(
            runner=FakeBW(
                [{"id": "infra-id", "name": "Infra"}],
                [
                    item(
                        "service",
                        "infra-id",
                        fields=[{"name": "token", "value": "custom-token"}],
                        password="login-password",
                    )
                ],
            ),
            sync=False,
        )

    def test_template_supports_bare_and_braced_references(self):
        rendered = bwenv.render_template(
            "a={{ op://Infra/service/token }}\nb=op://Infra/service/password\n",
            self.resolver,
        )
        self.assertEqual("a=custom-token\nb=login-password\n", rendered)

    def test_template_supports_bw_references(self):
        rendered = bwenv.render_template(
            "a={{ bw://Infra/service/token }}\nb=bw://Infra/service/password\n",
            self.resolver,
        )
        self.assertEqual("a=custom-token\nb=login-password\n", rendered)

    def test_atomic_output_requires_force_and_uses_requested_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "runtime.env"
            target.write_text("old", encoding="utf-8")
            with self.assertRaises(bwenv.OutputExistsError):
                bwenv.write_output(target, "new", mode=0o600, force=False, prompt=lambda _: False)
            bwenv.write_output(target, "new", mode=0o600, force=True)
            self.assertEqual("new", target.read_text(encoding="utf-8"))
            self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))

    def test_cli_inject_writes_a_restricted_file(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "runtime.env.tpl"
            output = Path(directory) / "runtime.env"
            template.write_text("TOKEN={{ op://Infra/service/token }}\n", encoding="utf-8")
            with patch.object(bwenv, "_resolver_from_args", return_value=self.resolver):
                self.assertEqual(
                    0,
                    bwenv.main(["--no-sync", "inject", "-i", str(template), "-o", str(output)]),
                )
            self.assertEqual("TOKEN=custom-token\n", output.read_text(encoding="utf-8"))
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))

    def test_cli_refusal_does_not_print_injected_value(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "runtime.env.tpl"
            output = Path(directory) / "runtime.env"
            template.write_text("TOKEN=op://Infra/service/token\n", encoding="utf-8")
            output.write_text("old", encoding="utf-8")
            stderr = StringIO()
            with patch.object(bwenv, "_resolver_from_args", return_value=self.resolver), redirect_stderr(stderr):
                self.assertEqual(
                    1,
                    bwenv.main(["--no-sync", "inject", "-i", str(template), "-o", str(output)]),
                )
            self.assertNotIn("custom-token", stderr.getvalue())

    def test_run_strips_bw_session_before_starting_the_child(self):
        received = {}

        def child_runner(command, env):
            received["command"] = command
            received["env"] = env
            return 0

        bwenv.run_command(
            ["example-service"],
            {"TOKEN": "op://Infra/service/token", "BW_SESSION": "session-sentinel"},
            self.resolver,
            child_runner,
        )
        self.assertEqual("custom-token", received["env"]["TOKEN"])
        self.assertNotIn("BW_SESSION", received["env"])

    def test_run_parser_keeps_command_arguments_after_separator(self):
        with patch.object(bwenv, "_resolver_from_args", return_value=self.resolver), patch.object(
            bwenv, "run_command", return_value=0
        ) as run_command:
            self.assertEqual(0, bwenv.main(["run", "--", "example-service", "--flag"]))
        self.assertEqual(["example-service", "--flag"], list(run_command.call_args.args[0]))

    def test_env_file_accepts_comments_quotes_and_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "# non-secret configuration\nTOKEN=op://Infra/service/token\n"
                "PLAIN=\"plain-value\"\nexport FLAG='enabled'\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {"TOKEN": "op://Infra/service/token", "PLAIN": "plain-value", "FLAG": "enabled"},
                bwenv.parse_env_file(path),
            )

    def test_env_file_rejects_invalid_syntax_without_echoing_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("NOT_VALID\n", encoding="utf-8")
            with self.assertRaisesRegex(bwenv.BWEnvError, "line 1"):
                bwenv.parse_env_file(path)

    def test_run_env_file_overrides_parent_and_removes_session(self):
        received = {}

        def run_stub(command, environment, resolver):
            received["command"] = command
            received["environment"] = environment
            return 0

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("TOKEN=op://Infra/service/token\nPLAIN=from-file\n", encoding="utf-8")
            with patch.object(bwenv, "_resolver_from_args", return_value=self.resolver), patch.object(
                bwenv, "run_command", side_effect=run_stub
            ):
                self.assertEqual(
                    0,
                    bwenv.main(["run", "--env-file", str(path), "--", "service"]),
                )
        self.assertEqual("op://Infra/service/token", received["environment"]["TOKEN"])
        self.assertEqual("from-file", received["environment"]["PLAIN"])


class KeychainTests(unittest.TestCase):
    def test_keychain_session_is_read_without_echoing_its_value(self):
        calls = []

        def runner(args):
            calls.append(args)
            return "session-sentinel"

        store = bwenv.KeychainSessionStore("bwenv.vaultwarden", runner=runner)
        self.assertEqual("session-sentinel", store.get())
        self.assertEqual(
            ["security", "find-generic-password", "-s", "bwenv.vaultwarden", "-a", "BW_SESSION", "-w"],
            calls[0],
        )

    @patch("bwenv.subprocess.run")
    def test_unlock_captures_only_the_session_not_the_interactive_prompt(self, mocked_run):
        mocked_run.return_value = type("Result", (), {"returncode": 0, "stdout": "session-sentinel\n"})()
        self.assertEqual("session-sentinel", bwenv._unlock_session())
        _, kwargs = mocked_run.call_args
        self.assertEqual(subprocess.PIPE, kwargs["stdout"])
        self.assertNotIn("capture_output", kwargs)

    def test_missing_keychain_entry_is_safe(self):
        def missing(_args):
            raise bwenv.KeychainError("macOS Keychain operation failed")

        with self.assertRaisesRegex(bwenv.KeychainError, "Keychain operation failed"):
            bwenv.KeychainSessionStore("missing", runner=missing).get()

    def test_linux_session_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}), patch("bwenv.sys.platform", "linux"):
                store = bwenv.KeychainSessionStore("test.service")
                with self.assertRaises(bwenv.KeychainError):
                    store.get()
                store.set("secret-session-token")
                self.assertEqual("secret-session-token", store.get())
                session_file = bwenv._linux_session_path("test.service")
                self.assertEqual(0o600, stat.S_IMODE(session_file.stat().st_mode))
                store.delete()
                self.assertFalse(session_file.exists())


class ProcessIntegrationTests(unittest.TestCase):
    def test_inject_uses_a_bw_executable_from_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bw = root / "bw"
            fake_bw.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "args = sys.argv[1:]\n"
                "if args == ['status']:\n"
                "    print(json.dumps({'status': 'unlocked'}))\n"
                "elif args == ['list', 'organizations']:\n"
                "    print(json.dumps([{'id': 'infra-id', 'name': 'Infra'}]))\n"
                "elif args == ['list', 'items']:\n"
                "    print(json.dumps([{'name': 'service', 'organizationId': 'infra-id', 'fields': [{'name': 'token', 'value': 'subprocess-token'}], 'login': {}}]))\n"
                "else:\n"
                "    print('SENTINEL_SECRET_FROM_BW_STDERR', file=sys.stderr)\n"
                "    raise SystemExit(12)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o755)
            environment = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}")
            result = subprocess.run(
                [sys.executable, str(Path(bwenv.__file__)), "--no-sync", "inject"],
                input="TOKEN={{ op://Infra/service/token }}\n",
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("TOKEN=subprocess-token\n", result.stdout)
            self.assertNotIn("SENTINEL_SECRET_FROM_BW_STDERR", result.stderr)


class InstallerTests(unittest.TestCase):
    def test_installer_publishes_only_explicit_bwenv_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            scripts = root / "scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(Path(bwenv.__file__), root / "bwenv.py")
            installer = scripts / "install-bwenv.sh"
            shutil.copy2(Path(__file__).parent / "scripts" / "install-bwenv.sh", installer)
            installer.chmod(0o755)
            bin_dir = Path(directory) / "bin"
            result = subprocess.run(
                ["sh", str(installer)],
                env=dict(os.environ, BWENV_BIN_DIR=str(bin_dir)),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            installed = bin_dir / "bwenv"
            self.assertFalse(installed.is_symlink())
            self.assertEqual(0o755, stat.S_IMODE(installed.stat().st_mode))
            self.assertFalse((bin_dir / "op").exists())
            source = root / "bwenv.py"
            source.write_text("this source was changed after installation\n", encoding="utf-8")
            result = subprocess.run(
                [str(installed), "--version"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("bwenv 2.1.0\n", result.stdout)
            source.unlink()
            result = subprocess.run(
                [str(installed), "--version"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)


class FallbackImportTests(unittest.TestCase):
    def fallback_file(self, directory, mode=0o600):
        source = Path(directory) / "fallback.json"
        source.write_text(
            bwenv.json.dumps(
                {
                    "secrets": {
                        "op://Infra/service/token": {"value": "DO_NOT_PRINT_TOKEN"},
                        "op://Infra/service/username": {"value": "DO_NOT_PRINT_USERNAME"},
                        "op://Personal Ops/other/key": {"value": "DO_NOT_PRINT_KEY"},
                        "OP_SERVICE_ACCOUNT_TOKEN": {"value": "DO_NOT_PRINT_OP_TOKEN"},
                    }
                }
            ),
            encoding="utf-8",
        )
        source.chmod(mode)
        return source

    def test_plan_groups_fields_and_excludes_non_op_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = bwenv.load_fallback_import_plan(self.fallback_file(directory))
        self.assertEqual(3, plan.reference_count)
        self.assertEqual(1, plan.skipped_non_op_count)
        self.assertEqual(2, len(plan.items))
        self.assertEqual(["token", "username"], [field.name for field in plan.items[0].fields])
        self.assertEqual(
            [
                "op://Infra/service",
                "op://Infra/service/token",
                "op://Infra/service/username",
            ],
            list(plan.items[0].source_uris),
        )

    def test_dry_run_prints_only_structural_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fallback_file(directory)
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, bwenv.main(["import-1password-fallback", "--file", str(source)]))
            plan = bwenv.load_fallback_import_plan(source)
        self.assertIn(f"plan digest: {plan.digest}", output.getvalue())
        self.assertNotIn("DO_NOT_PRINT", output.getvalue())

    def test_apply_requires_the_exact_dry_run_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fallback_file(directory)
            stderr = StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(
                    1,
                    bwenv.main(
                        [
                            "--keychain-service",
                            "test-service",
                            "import-1password-fallback",
                            "--file",
                            str(source),
                            "--apply",
                            "--plan-digest",
                            "0" * 64,
                            "--receipt",
                            str(Path(directory) / "receipt"),
                        ]
                    ),
                )
        self.assertIn("plan digest", stderr.getvalue())
        self.assertNotIn("DO_NOT_PRINT", stderr.getvalue())

    def test_dry_run_never_prints_fallback_values(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fallback_file(directory)
            stdout = StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(0, bwenv.main(["import-1password-fallback", "--file", str(source)]))
        output = stdout.getvalue()
        self.assertIn("references: 3", output)
        self.assertIn("Infra: 1 item, 2 fields", output)
        self.assertNotIn("DO_NOT_PRINT", output)

    def test_import_rejects_a_group_or_world_readable_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fallback_file(directory, mode=0o644)
            with self.assertRaisesRegex(bwenv.ImportValidationError, "permissions"):
                bwenv.load_fallback_import_plan(source)

    def test_apply_creates_only_preflighted_organization_items(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = bwenv.load_fallback_import_plan(self.fallback_file(directory))
        calls = []

        def runner(args, env, input_text):
            calls.append((args, env.copy(), input_text))
            if args == ["status"]:
                return '{"status":"unlocked"}'
            if args == ["list", "organizations"]:
                return bwenv.json.dumps([
                    {"id": "infra-id", "name": "Infra"},
                    {"id": "ops-id", "name": "Personal Ops"},
                ])
            if args == ["list", "items"]:
                return "[]"
            if args == ["list", "org-collections", "--organizationid", "infra-id"]:
                return bwenv.json.dumps([{"id": "infra-collection", "name": "Deployments"}])
            if args == ["list", "org-collections", "--organizationid", "ops-id"]:
                return bwenv.json.dumps([{"id": "ops-collection", "name": "Deployments"}])
            if args == ["get", "template", "item"]:
                return '{"type":1,"name":null,"fields":null,"login":null}'
            if args == ["encode"]:
                return "encoded-item"
            if args == ["create", "item"]:
                return '{"id":"created"}'
            raise AssertionError(f"unexpected bw call: {args}")

        writer = bwenv.VaultImportWriter("session-sentinel", sync=False, runner=runner)
        writer.apply(plan, {"Infra": "Deployments", "Personal Ops": "Deployments"})
        creates = [call for call in calls if call[0] == ["create", "item"]]
        self.assertEqual(2, len(creates))
        self.assertTrue(all(call[1]["BW_SESSION"] == "session-sentinel" for call in calls))
        encoded_payloads = [call[2] for call in calls if call[0] == ["encode"]]
        self.assertTrue(any("DO_NOT_PRINT_TOKEN" in payload for payload in encoded_payloads))

    def test_apply_refuses_collision_before_any_create(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = bwenv.load_fallback_import_plan(self.fallback_file(directory))
        calls = []

        def runner(args, env, input_text):
            calls.append(args)
            if args == ["status"]:
                return '{"status":"unlocked"}'
            if args == ["list", "organizations"]:
                return bwenv.json.dumps([
                    {"id": "infra-id", "name": "Infra"},
                    {"id": "ops-id", "name": "Personal Ops"},
                ])
            if args == ["list", "items"]:
                return bwenv.json.dumps([{"organizationId": "infra-id", "name": "service"}])
            if args == ["list", "org-collections", "--organizationid", "infra-id"]:
                return bwenv.json.dumps([{"id": "infra-collection", "name": "Deployments"}])
            if args == ["list", "org-collections", "--organizationid", "ops-id"]:
                return bwenv.json.dumps([{"id": "ops-collection", "name": "Deployments"}])
            raise AssertionError(f"unexpected bw call: {args}")

        writer = bwenv.VaultImportWriter("session-sentinel", sync=False, runner=runner)
        with self.assertRaises(bwenv.ImportCollisionError):
            writer.apply(plan, {"Infra": "Deployments", "Personal Ops": "Deployments"})
        self.assertNotIn(["create", "item"], calls)

    def test_partial_apply_writes_receipt_and_can_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fallback_file(directory)
            plan = bwenv.load_fallback_import_plan(source)
            receipt = Path(directory) / "import-receipt.json"
            state = {"items": [], "create_count": 0, "fail_once": True}

            def runner(args, env, input_text):
                if args == ["status"]:
                    return '{"status":"unlocked"}'
                if args == ["list", "organizations"]:
                    return bwenv.json.dumps([
                        {"id": "infra-id", "name": "Infra"},
                        {"id": "ops-id", "name": "Personal Ops"},
                    ])
                if args == ["list", "items"]:
                    return bwenv.json.dumps(state["items"])
                if args == ["list", "org-collections", "--organizationid", "infra-id"]:
                    return '[{"id":"infra-collection","name":"Deployments"}]'
                if args == ["list", "org-collections", "--organizationid", "ops-id"]:
                    return '[{"id":"ops-collection","name":"Deployments"}]'
                if args == ["get", "template", "item"]:
                    return '{"type":1,"name":null,"fields":null,"login":null}'
                if args == ["encode"]:
                    return input_text
                if args == ["create", "item"]:
                    state["create_count"] += 1
                    if state["fail_once"] and state["create_count"] == 2:
                        state["fail_once"] = False
                        raise bwenv.BWEnvError("Bitwarden command failed: create item")
                    created_id = f"created-{state['create_count']}"
                    payload = bwenv.json.loads(input_text)
                    state["items"].append({
                        "id": created_id,
                        "organizationId": payload["organizationId"],
                        "name": payload["name"],
                    })
                    return bwenv.json.dumps({"id": created_id})
                raise AssertionError(f"unexpected bw call: {args}")

            writer = bwenv.VaultImportWriter("session-sentinel", sync=False, runner=runner)
            with self.assertRaises(bwenv.BWEnvError):
                writer.apply(
                    plan,
                    {"Infra": "Deployments", "Personal Ops": "Deployments"},
                    receipt_path=receipt,
                )
            self.assertEqual(0o600, stat.S_IMODE(receipt.stat().st_mode))
            saved = bwenv.json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(["created", "creating"], [
                entry["status"] for entry in saved["items"]
            ])
            self.assertEqual("", saved["items"][1]["id"])

            writer.apply(
                plan,
                {"Infra": "Deployments", "Personal Ops": "Deployments"},
                receipt_path=receipt,
            )
            saved = bwenv.json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(2, len(saved["items"]))

    def test_successful_create_with_invalid_response_is_recoverable_and_reversible(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fallback.json"
            source.write_text(
                bwenv.json.dumps({
                    "secrets": {
                        "op://Infra/service/token": {"value": "[REDACTED:token]"},
                    }
                }),
                encoding="utf-8",
            )
            source.chmod(0o600)
            plan = bwenv.load_fallback_import_plan(source)
            receipt = Path(directory) / "receipt.json"
            state = {"items": [], "invalid_once": True, "deletes": []}

            def runner(args, env, input_text):
                if args == ["status"]:
                    return '{"status":"unlocked"}'
                if args == ["list", "organizations"]:
                    return '[{"id":"infra-id","name":"Infra"}]'
                if args == ["list", "items"]:
                    return bwenv.json.dumps(state["items"])
                if args == ["list", "org-collections", "--organizationid", "infra-id"]:
                    return '[{"id":"infra-collection","name":"Deployments"}]'
                if args == ["get", "template", "item"]:
                    return '{"type":1,"name":null,"fields":null,"login":null}'
                if args == ["encode"]:
                    return input_text
                if args == ["create", "item"]:
                    payload = bwenv.json.loads(input_text)
                    state["items"].append({
                        "id": "created-after-invalid-response",
                        "organizationId": payload["organizationId"],
                        "name": payload["name"],
                        "login": payload["login"],
                    })
                    if state["invalid_once"]:
                        state["invalid_once"] = False
                        return "not-json"
                    return '{"id":"created-after-invalid-response"}'
                if args[:2] == ["delete", "item"]:
                    identifier = args[2]
                    state["deletes"].append(identifier)
                    state["items"] = [item for item in state["items"] if item["id"] != identifier]
                    return ""
                raise AssertionError(f"unexpected bw call: {args}")

            writer = bwenv.VaultImportWriter("session-sentinel", sync=False, runner=runner)
            with self.assertRaisesRegex(bwenv.BWEnvError, "invalid created-item JSON"):
                writer.apply(
                    plan, {"Infra": "Deployments"}, receipt_path=receipt
                )
            pending = bwenv.json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual("creating", pending["items"][0]["status"])
            self.assertEqual("", pending["items"][0]["id"])

            writer.apply(plan, {"Infra": "Deployments"}, receipt_path=receipt)
            recovered = bwenv.json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual("created", recovered["items"][0]["status"])
            self.assertEqual(["created-after-invalid-response"], [
                item["id"] for item in state["items"]
            ])

            writer.rollback(receipt)
            self.assertEqual(["created-after-invalid-response"], state["deletes"])
            self.assertEqual([], state["items"])

    def test_unmarked_concurrent_item_is_never_adopted_or_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fallback.json"
            source.write_text(
                '{"secrets":{"op://Infra/service/token":{"value":"[REDACTED:token]"}}}',
                encoding="utf-8",
            )
            source.chmod(0o600)
            plan = bwenv.load_fallback_import_plan(source)
            receipt = Path(directory) / "receipt.json"
            marker = bwenv.import_marker(plan.digest, "Infra", "service")
            receipt.write_text(
                bwenv.json.dumps({
                    "version": 1,
                    "plan_digest": plan.digest,
                    "items": [{
                        "organization": "Infra",
                        "name": "service",
                        "id": "",
                        "status": "creating",
                        "marker": marker,
                    }],
                }),
                encoding="utf-8",
            )
            receipt.chmod(0o600)
            calls = []

            def runner(args, env, input_text):
                calls.append(args)
                if args == ["status"]:
                    return '{"status":"unlocked"}'
                if args == ["list", "organizations"]:
                    return '[{"id":"infra-id","name":"Infra"}]'
                if args == ["list", "items"]:
                    return '[{"id":"operator-created","organizationId":"infra-id","name":"service","login":{"uris":[]}}]'
                if args == ["list", "org-collections", "--organizationid", "infra-id"]:
                    return '[{"id":"infra-collection","name":"Deployments"}]'
                raise AssertionError(args)

            writer = bwenv.VaultImportWriter("session-sentinel", sync=False, runner=runner)
            with self.assertRaises(bwenv.ImportCollisionError):
                writer.apply(plan, {"Infra": "Deployments"}, receipt_path=receipt)
            with self.assertRaises(bwenv.ImportCollisionError):
                writer.rollback(receipt)
            self.assertNotIn(["delete", "item", "operator-created"], calls)

    def test_pending_receipt_without_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(
                '{"version":1,"plan_digest":"' + "0" * 64 + '","items":['
                '{"organization":"Infra","name":"service","id":"","status":"creating"}]}',
                encoding="utf-8",
            )
            receipt.chmod(0o600)
            with self.assertRaisesRegex(bwenv.ImportValidationError, "no marker"):
                bwenv._load_receipt(receipt)

    def test_apply_persists_compatibility_source_uris(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = bwenv.load_fallback_import_plan(self.fallback_file(directory))
            encoded = []

            def runner(args, env, input_text):
                if args == ["status"]:
                    return '{"status":"unlocked"}'
                if args == ["list", "organizations"]:
                    return '[{"id":"infra-id","name":"Infra"},{"id":"ops-id","name":"Personal Ops"}]'
                if args == ["list", "items"]:
                    return "[]"
                if args == ["list", "org-collections", "--organizationid", "infra-id"]:
                    return '[{"id":"infra-collection","name":"Deployments"}]'
                if args == ["list", "org-collections", "--organizationid", "ops-id"]:
                    return '[{"id":"ops-collection","name":"Deployments"}]'
                if args == ["get", "template", "item"]:
                    return '{"type":1,"name":null,"fields":null,"login":null}'
                if args == ["encode"]:
                    encoded.append(bwenv.json.loads(input_text))
                    return "encoded"
                if args == ["create", "item"]:
                    return '{"id":"created"}'
                raise AssertionError(f"unexpected bw call: {args}")

            bwenv.VaultImportWriter("session-sentinel", sync=False, runner=runner).apply(
                plan, {"Infra": "Deployments", "Personal Ops": "Deployments"}
            )
            self.assertEqual(
                [
                    "op://Infra/service",
                    "op://Infra/service/token",
                    "op://Infra/service/username",
                    bwenv.import_marker(plan.digest, "Infra", "service"),
                ],
                [uri["uri"] for uri in encoded[0]["login"]["uris"]],
            )
            self.assertTrue(all(
                uri["match"] == bwenv.URI_MATCH_EXACT
                for uri in encoded[0]["login"]["uris"]
            ))

    def test_rollback_is_idempotent_and_verifies_receipt_ids_only(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(
                '{"version":1,"plan_digest":"' + "0" * 64 + '","items":['
                '{"organization":"Infra","name":"service","id":"created-1","status":"created"}]}',
                encoding="utf-8",
            )
            receipt.chmod(0o600)
            state = {"items": [{"id": "created-1", "organizationId": "infra-id", "name": "service"}]}
            deleted = []

            def runner(args, env, input_text):
                if args == ["status"]:
                    return '{"status":"unlocked"}'
                if args == ["list", "items"]:
                    return bwenv.json.dumps(state["items"])
                if args[:2] == ["delete", "item"]:
                    identifier = args[2]
                    deleted.append(identifier)
                    state["items"] = [item for item in state["items"] if item["id"] != identifier]
                    return ""
                raise AssertionError(f"unexpected bw call: {args}")

            writer = bwenv.VaultImportWriter("session-sentinel", sync=False, runner=runner)
            writer.rollback(receipt)
            writer.rollback(receipt)
            self.assertEqual(["created-1"], deleted)
            saved = bwenv.json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual("deleted", saved["items"][0]["status"])
            self.assertEqual([], state["items"])


if __name__ == "__main__":
    unittest.main()
