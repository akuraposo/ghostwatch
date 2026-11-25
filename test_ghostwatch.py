#!/usr/bin/env python3
"""Unit and HTTP integration tests for GhostWatch v2.1."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import ghostwatch


class GhostWatchAuditTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._orig_state_file = ghostwatch.STATE_FILE
        ghostwatch.STATE_FILE = Path(self._td.name) / "state.json"
        ghostwatch.AUDIT_HISTORY.clear()
        ghostwatch.REMEDIATED_ISSUES.clear()
        ghostwatch.PREVIEW_REMEDIATED_ISSUES.clear()
        ghostwatch.AUDITED_REPOS.clear()
        ghostwatch.LAST_AUDIT = None

    def tearDown(self):
        ghostwatch.STATE_FILE = self._orig_state_file
        self._td.cleanup()

    def test_safe_env_lookups_and_function_calls_do_not_trigger_false_positives(self):
        commits = [
            {
                "sha": "3333333cccc",
                "commit": {"message": "refactor: load secrets from env", "author": {"date": "2026-11-25T00:00:00Z"}},
                "files": [
                    {
                        "filename": "src/config.py",
                        "patch": (
                            "+ API_KEY = os.environ['API_KEY']\n"
                            "+ api_key = 'process.env.MY_KEY'\n"
                            "+ password = 'changeme123'\n"
                            "+ password = fetchSecretFromVault()\n"
                            "+ api_key = loadConfigValue()\n"
                            "+ const cfg = { password: userPasswordInput, api_key: client_secret_var, timeout: 5000 };"
                        ),
                    }
                ],
            }
        ]
        findings = ghostwatch.analyze_commits("owner/safe", commits)
        self.assertEqual(findings, [])

    def test_unquoted_alphanumeric_secret_detected(self):
        commits = [
            {
                "sha": "6666666ffff",
                "commit": {"message": "chore: add db env", "author": {"date": "2026-11-25T00:00:00Z"}},
                "files": [
                    {"filename": "deploy/env.conf", "patch": "+ password=hunter2secret99"},
                ],
            }
        ]
        findings = ghostwatch.analyze_commits("owner/env", commits)
        self.assertEqual(len(findings), 1)
        self.assertNotIn("hunter2secret99", findings[0]["evidence"])

    def test_quoted_secrets_containing_dots_are_detected(self):
        commits = [
            {
                "sha": "5555555eeee",
                "commit": {"message": "chore: config", "author": {"date": "2026-11-25T00:00:00Z"}},
                "files": [
                    {
                        "filename": "src/auth.py",
                        "patch": "+ secret = 'Tr0ub4dor.9x!'\n+ api_key = 'sk.prod.9f8e7d6c5b4a'",
                    }
                ],
            }
        ]
        findings = ghostwatch.analyze_commits("owner/dots", commits)
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertNotIn("Tr0ub4dor.9x!", f["evidence"])
            self.assertNotIn("9f8e7d6c5b4a", f["evidence"])

    def test_stripe_underscore_and_multi_secret_patch_all_detected(self):
        stripe_tok = "sk_live_" + "51HabcDEF1234567890abcdef"
        aws_tok = "AKIA" + "IOSFODNN7EXAMPLE"
        gh_tok = "ghp_" + "1234567890abcdefghij123456"
        commits = [
            {
                "sha": "4444444dddd",
                "commit": {"message": "feat: billing", "author": {"date": "2026-11-25T00:00:00Z"}},
                "files": [
                    {
                        "filename": "src/pay.py",
                        "patch": (
                            f"+ STRIPE_KEY = '{stripe_tok}'\n"
                            f"+ AWS = '{aws_tok}'\n"
                            f"+ GH = '{gh_tok}'"
                        ),
                    }
                ],
            }
        ]
        findings = ghostwatch.analyze_commits("owner/pay", commits)
        self.assertEqual(len(findings), 3)
        for f in findings:
            self.assertNotIn("51HabcDEF1234567890abcdef", f["evidence"])
            self.assertNotIn("IOSFODNN7EXAMPLE", f["evidence"])

    def test_secret_redaction_never_leaks_full_value(self):
        raw_secret = "sk-live-" + "9f8e7d6c5b4a3210fedcba"
        redacted = ghostwatch.redact_secret(raw_secret)
        self.assertNotIn("9f8e7d6c5b4a", redacted)
        self.assertTrue(redacted.startswith("sk-l"))
        self.assertTrue(redacted.endswith("dcba"))

    def test_analyze_commits_detects_patch_secret_and_sensitive_file(self):
        gh_tok = "ghp_" + "1234567890abcdefghij123456"
        commits = [
            {
                "sha": "1111111aaaa",
                "commit": {"message": "feat: add config", "author": {"date": "2026-11-25T00:00:00Z"}},
                "files": [
                    {"filename": ".env.production", "patch": "+ DB_HOST=localhost"},
                    {"filename": "src/app.py", "patch": f"+ KEY = '{gh_tok}'"},
                ],
            }
        ]
        findings = ghostwatch.analyze_commits("owner/demo", commits)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["severity"] == "high" for f in findings))
        # Ensure full token is redacted in evidence
        for f in findings:
            self.assertNotIn(gh_tok, f["evidence"])

    def test_analyze_pull_requests_flags_risky_and_unreviewed_prs(self):
        prs = [
            {
                "number": 7,
                "title": "hotfix: bypass auth for partner",
                "body": "quick workaround",
                "draft": False,
                "created_at": "2026-11-24T12:00:00Z",
                "html_url": "https://github.com/owner/demo/pull/7",
                "requested_reviewers": [],
            },
            {
                "number": 8,
                "title": "feat: add metrics endpoint",
                "body": "clean change",
                "draft": False,
                "created_at": "2026-11-24T12:00:00Z",
                "html_url": "https://github.com/owner/demo/pull/8",
                "requested_reviewers": [],
            },
        ]
        findings = ghostwatch.analyze_pull_requests("owner/demo", prs)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[1]["severity"], "low")

    def test_demo_audit_and_markdown_export(self):
        audit = ghostwatch.run_audit(force_demo=True)
        self.assertEqual(audit["mode"], "local-preview")
        self.assertGreaterEqual(audit["summary"]["repos_audited"], 4)
        self.assertGreaterEqual(audit["summary"]["high_findings"], 3)
        self.assertEqual(len(audit["history"]), 1)

        md = ghostwatch.render_markdown_report(audit)
        self.assertIn("# GhostWatch Security Audit Report", md)
        self.assertIn("akuraposo/payments-worker", md)
        self.assertNotIn("9f8e7d6c5b4a3210fedcba", md)

    def test_remediation_rejects_invalid_repo(self):
        with self.assertRaises(ValueError):
            ghostwatch.create_remediation_issue({"repo": "not a valid repo!!!"})

    def test_unquoted_secret_assignment_and_webhook_secret_detected(self):
        wh_tok = "whsec_" + "demo9876543210"
        commits = [
            {
                "sha": "2222222bbbb",
                "commit": {"message": "chore: add webhook config", "author": {"date": "2026-11-25T00:00:00Z"}},
                "files": [
                    {"filename": "config/prod.ini", "patch": f"+ STRIPE_WEBHOOK_SECRET={wh_tok}"},
                ],
            }
        ]
        findings = ghostwatch.analyze_commits("owner/demo", commits)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertNotIn(wh_tok, findings[0]["evidence"])


class MockGatewayHandler(ghostwatch.BaseHTTPRequestHandler):
    def _send(self, code: int, obj: object):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/user":
            self._send(200, {"login": "mockdev"})
        elif self.path.startswith("/user/repos"):
            repos = [
                {
                    "full_name": f"mockdev/repo-{i}",
                    "private": True,
                    "language": "Python",
                    "pushed_at": "2026-11-25T00:00:00Z",
                    "html_url": f"https://github.com/mockdev/repo-{i}",
                    "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
                }
                for i in range(1, 7)
            ]
            self._send(200, repos)
        elif "/commits?" in self.path:
            self._send(200, [
                {"sha": "abc1234", "commit": {"message": "feat: ok", "author": {"date": "2026-11-25T00:00:00Z"}}},
                {"sha": "def5678", "commit": {"message": "docs: readme", "author": {"date": "2026-11-24T00:00:00Z"}}},
                {"sha": "ghi9012", "commit": {"message": "chore: old commit", "author": {"date": "2026-11-23T00:00:00Z"}}},
            ])
        elif "/commits/abc1234" in self.path or "/commits/def5678" in self.path:
            self._send(200, {"sha": "abc1234", "files": []})
        elif "/commits/ghi9012" in self.path:
            if "repo-1" in self.path:
                self._send(200, {
                    "sha": "ghi9012",
                    "files": [{"filename": "old.py", "patch": "+ OLD_KEY = 'AKIAIOSFODNN7EXAMPLE'"}],
                })
            else:
                self._send(200, {"sha": "ghi9012", "files": []})
        elif "/pulls?" in self.path:
            self._send(200, [])
        else:
            self._send(404, {"message": "Not Found"})

    def do_POST(self):
        if self.path.endswith("/issues"):
            self._send(403, {"message": "Resource not accessible by connector"})
        else:
            self._send(404, {"message": "Not Found"})

    def log_message(self, fmt, *args):
        pass


class GhostWatchMockGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gw = ThreadingHTTPServer(("127.0.0.1", 0), MockGatewayHandler)
        cls.gw_url = f"http://127.0.0.1:{cls.gw.server_address[1]}"
        cls.gw_thread = threading.Thread(target=cls.gw.serve_forever, daemon=True)
        cls.gw_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.gw.shutdown()
        cls.gw.server_close()

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.orig_state = ghostwatch.STATE_FILE
        ghostwatch.STATE_FILE = Path(self._td.name) / "mock_state.json"
        ghostwatch.LAST_AUDIT = None
        ghostwatch.AUDIT_HISTORY.clear()
        ghostwatch.REMEDIATED_ISSUES.clear()
        ghostwatch.PREVIEW_REMEDIATED_ISSUES.clear()
        ghostwatch.AUDITED_REPOS.clear()
        self.orig_gw = ghostwatch.GATEWAY_BASE
        ghostwatch.GATEWAY_BASE = self.gw_url

    def tearDown(self):
        ghostwatch.GATEWAY_BASE = self.orig_gw
        ghostwatch.STATE_FILE = self.orig_state
        self._td.cleanup()

    def test_sixth_repo_and_deeper_commit_diffs_are_scanned(self):
        audit = ghostwatch.run_audit(force_demo=False)
        self.assertEqual(audit["mode"], "live-sprites-connector")
        self.assertEqual(len(audit["repos"]), 6)
        sixth = audit["repos"][5]
        self.assertEqual(sixth["full_name"], "mockdev/repo-6")
        self.assertEqual(sixth["commits_checked"], 3)
        # 3rd commit on mockdev/repo-1 leaked an AWS key — verify deeper diff scan catches it
        repo1_findings = [f for f in audit["findings"] if f["repo"] == "mockdev/repo-1"]
        self.assertEqual(len(repo1_findings), 1)
        self.assertIn("AWS Access Key ID", repo1_findings[0]["reason"])

    def test_http_403_on_remediation_is_not_masked_as_fake_201(self):
        # Cold-start remediation before any scan must be rejected (prevents arbitrary victim repo spam)
        with self.assertRaises(ValueError):
            ghostwatch.create_remediation_issue({"repo": "unrelated-org/victim-repo", "reason": "Spam"})

        # Preview demo=True cannot spoof an un-audited victim repo or bypass live audit mode
        with self.assertRaises(ValueError):
            ghostwatch.create_remediation_issue({"repo": "unrelated-org/victim-repo", "demo": True})

        # After scanning mockdev/repo-1, gateway 403 must propagate as GatewayHTTPError (NOT fake 201)
        audit = ghostwatch.run_audit(force_demo=False)
        ghostwatch.LAST_AUDIT = audit
        with self.assertRaises(ValueError):
            ghostwatch.create_remediation_issue({"repo": "mockdev/repo-1", "demo": True})
        with self.assertRaises(ghostwatch.GatewayHTTPError) as ctx:
            ghostwatch.create_remediation_issue({"repo": "mockdev/repo-1", "reason": "Test"})
        self.assertEqual(ctx.exception.status, 403)

    def test_persistent_state_roundtrip_and_ai_triage_fallback(self):
        import tempfile
        from pathlib import Path

        orig_state = ghostwatch.STATE_FILE
        orig_or = ghostwatch.OPENROUTER_GW
        orig_ollama = ghostwatch.OLLAMA_URL
        try:
            with tempfile.TemporaryDirectory() as td:
                ghostwatch.AUDIT_HISTORY.clear()
                ghostwatch.STATE_FILE = Path(td) / "state.json"
                ghostwatch.run_audit(force_demo=True)
                self.assertTrue(ghostwatch.STATE_FILE.exists())
                ghostwatch.AUDIT_HISTORY.clear()
                ghostwatch.load_persisted_state()
                self.assertEqual(len(ghostwatch.AUDIT_HISTORY), 1)

            # Force unreachable OpenRouter & Ollama -> honest local-playbook (trace=None)
            ghostwatch.OPENROUTER_GW = "http://127.0.0.1:1"
            ghostwatch.OLLAMA_URL = "http://127.0.0.1:1"
            res = ghostwatch.triage_finding({
                "repo": "mockdev/repo-1",
                "category": "secret",
                "severity": "high",
                "reason": "Leaked API key",
            })
            self.assertEqual(res["engine"], "local-playbook")
            self.assertIsNone(res["trace"])
            self.assertGreaterEqual(len(res["fix_steps"]), 2)
        finally:
            ghostwatch.STATE_FILE = orig_state
            ghostwatch.OPENROUTER_GW = orig_or
            ghostwatch.OLLAMA_URL = orig_ollama


class GhostWatchHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory()
        cls._orig_state_file = ghostwatch.STATE_FILE
        ghostwatch.STATE_FILE = Path(cls._td.name) / "http_state.json"
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ghostwatch.Handler)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        ghostwatch.STATE_FILE = cls._orig_state_file
        cls._td.cleanup()

    def test_endpoints_end_to_end(self):
        ghostwatch.REMEDIATED_ISSUES.clear()
        ghostwatch.PREVIEW_REMEDIATED_ISSUES.clear()
        ghostwatch.AUDITED_REPOS.clear()
        ghostwatch.LAST_AUDIT = None

        # 1. Dashboard HTML
        with urllib.request.urlopen(f"{self.base}/") as r:
            self.assertEqual(r.status, 200)
            html = r.read().decode("utf-8")
            self.assertIn("GhostWatch", html)
            self.assertIn("escapeHtml", html)
            self.assertIn("btn-demo", html)
            self.assertIn("history-strip", html)
            self.assertIn("auth-token-input", html)

        # 2. Scan endpoint (demo mode)
        with urllib.request.urlopen(f"{self.base}/api/scan?demo=1") as r:
            self.assertEqual(r.status, 200)
            audit = json.loads(r.read().decode("utf-8"))
            self.assertEqual(audit["mode"], "local-preview")
            self.assertGreater(len(audit["findings"]), 0)

        # 3. Env proof endpoint
        with urllib.request.urlopen(f"{self.base}/api/env-proof") as r:
            self.assertEqual(r.status, 200)
            proof = json.loads(r.read().decode("utf-8"))
            self.assertIn("credential_files_checked", proof)

        # 4. Markdown report endpoint
        with urllib.request.urlopen(f"{self.base}/api/report.md") as r:
            self.assertEqual(r.status, 200)
            self.assertIn("text/markdown", r.headers.get("Content-Type", ""))
            md = r.read().decode("utf-8")
            self.assertIn("GhostWatch Security Audit Report", md)

        # 5. Remediation POST endpoint (uses server-verified finding metadata + isolates preview state)
        finding = audit["findings"][0]
        req = urllib.request.Request(
            f"{self.base}/api/remediate/issue",
            data=json.dumps({
                "finding_id": finding["id"],
                "repo": "spoofed/other-repo",
                "ref": finding["ref"],
                "severity": finding["severity"],
                "reason": "SPOOFED REASON",
                "message": finding["message"],
                "evidence": finding["evidence"],
                "demo": True,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 201)
            res = json.loads(r.read().decode("utf-8"))
            self.assertIn("issue_number", res)
            self.assertNotIn("SPOOFED REASON", res["title"])
            self.assertIn(finding["reason"], res["title"])
            self.assertEqual(res["trace"]["method"], "POST")
            self.assertIn("none — injected by Fly.io Sprites Gateway", res["trace"]["authorization_header"])
            self.assertNotIn(finding["id"], ghostwatch.REMEDIATED_ISSUES)
            self.assertIn(finding["id"], ghostwatch.PREVIEW_REMEDIATED_ISSUES)

        # 6. Duplicate remediation is deduplicated (200, no duplicate issue)
        with urllib.request.urlopen(req) as r2:
            self.assertEqual(r2.status, 200)
            res2 = json.loads(r2.read().decode("utf-8"))
            self.assertTrue(res2.get("deduplicated"))
            self.assertEqual(res2["issue_number"], res["issue_number"])

        # 7. SARIF 2.1.0 report endpoint
        with urllib.request.urlopen(f"{self.base}/api/report.sarif") as r:
            self.assertEqual(r.status, 200)
            sarif = json.loads(r.read().decode("utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreater(len(sarif["runs"][0]["results"]), 0)

        # 8. CSRF Content-Type (415), Origin: null (403), invalid UTF-8 (400), oversized (413)
        bad_ct = urllib.request.Request(
            f"{self.base}/api/remediate/issue",
            data=b'{"repo":"akuraposo/loopclose"}',
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx_ct:
            urllib.request.urlopen(bad_ct)
        self.assertEqual(ctx_ct.exception.code, 415)

        null_origin = urllib.request.Request(
            f"{self.base}/api/triage",
            data=b'{"repo":"akuraposo/loopclose"}',
            headers={"Content-Type": "application/json", "Origin": "null"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx_null:
            urllib.request.urlopen(null_origin)
        self.assertEqual(ctx_null.exception.code, 403)

        bad_utf8 = urllib.request.Request(
            f"{self.base}/api/triage",
            data=b"\xff\xfe\xfd",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx_utf:
            urllib.request.urlopen(bad_utf8)
        self.assertEqual(ctx_utf.exception.code, 400)

        big_req = urllib.request.Request(
            f"{self.base}/api/triage",
            data=b'{"x":"' + (b"a" * 40000) + b'"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx_big:
            urllib.request.urlopen(big_req)
        self.assertEqual(ctx_big.exception.code, 413)

        # 9. Dashboard token auth (401 without header, 200 with X-GhostWatch-Token)
        orig_tok = ghostwatch.DASHBOARD_TOKEN
        try:
            ghostwatch.DASHBOARD_TOKEN = "super-secret-dash-token"
            with self.assertRaises(urllib.error.HTTPError) as ctx_unauth:
                urllib.request.urlopen(f"{self.base}/api/status")
            self.assertEqual(ctx_unauth.exception.code, 401)

            auth_req = urllib.request.Request(
                f"{self.base}/api/status",
                headers={"X-GhostWatch-Token": "super-secret-dash-token"},
            )
            with urllib.request.urlopen(auth_req) as r_auth:
                self.assertEqual(r_auth.status, 200)
                st_auth = json.loads(r_auth.read().decode("utf-8"))
                self.assertTrue(st_auth["auth_enabled"])
        finally:
            ghostwatch.DASHBOARD_TOKEN = orig_tok

        # 9. History & status endpoints
        with urllib.request.urlopen(f"{self.base}/api/status") as r:
            status = json.loads(r.read().decode("utf-8"))
            self.assertEqual(status["version"], "2.1")
            self.assertTrue(status["has_last_audit"])


if __name__ == "__main__":
    unittest.main()
