#!/usr/bin/env python3
"""GhostWatch — Zero-Credential Personal GitHub Watchdog for Fly.io Sprites.

Routes every GitHub API call (read AND write remediation) through the Fly.io
Sprites Connector Gateway:
    https://api.sprites.dev/v1/gateway/github/<path>

No GitHub token, OAuth secret, or API key ever enters the Sprite filesystem
or environment variables. Runs on Python 3 stdlib with zero external dependencies.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hmac
import json
import math
import os
import re
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
STATE_FILE = Path(os.environ.get("GHOSTWATCH_STATE_FILE", str(ROOT / "ghostwatch_state.json")))
DASHBOARD_TOKEN = os.environ.get("GHOSTWATCH_DASHBOARD_TOKEN", "").strip()
MAX_REPOS = 6
MAX_COMMIT_DIFFS_PER_REPO = 5
MAX_POST_BYTES = 32_768
STATE_LOCK = threading.Lock()
OPENROUTER_GW = os.environ.get("SPRITES_OPENROUTER_GATEWAY", "https://api.sprites.dev/v1/gateway/openrouter").rstrip("/")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
TRIAGE_MODEL = os.environ.get("GHOSTWATCH_MODEL", "google/gemini-2.5-flash")
OLLAMA_MODEL = os.environ.get("GHOSTWATCH_OLLAMA_MODEL", "llama3.2")


class GatewayHTTPError(Exception):
    """Raised when the Sprites Connector Gateway returns a real HTTP 4xx/5xx error."""

    def __init__(self, status: int, message: str, trace: dict[str, Any]):
        super().__init__(message)
        self.status = status
        self.message = message
        self.trace = trace

# Fly.io Sprites Gateway base URL (override via SPRITES_GATEWAY_BASE if using a named connection_id)
GATEWAY_BASE = os.environ.get(
    "SPRITES_GATEWAY_BASE",
    "https://api.sprites.dev/v1/gateway/github",
).rstrip("/")

SECRET_ENV_PATTERNS = re.compile(
    r"(GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|"
    r"AWS_SECRET_ACCESS_KEY|STRIPE_SECRET|FLY_API_TOKEN|SPRITES_TOKEN|DATABASE_URL|"
    r"API_KEY|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN)",
    re.IGNORECASE,
)

CREDENTIAL_FILE_CANDIDATES = [
    ROOT / ".env",
    ROOT / ".env.local",
    Path.home() / ".git-credentials",
    Path.home() / ".netrc",
    Path.home() / ".config" / "gh" / "hosts.yml",
    Path.home() / ".ssh" / "id_rsa",
    Path.home() / ".ssh" / "id_ed25519",
    Path.home() / ".aws" / "credentials",
    Path.home() / ".npmrc",
]

# High-confidence provider secret prefixes (value-scoped via named group `val`)
PROVIDER_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?P<val>ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "GitHub Personal Access Token"),
    (re.compile(r"\b(?P<val>AKIA[0-9A-Z]{16})\b"), "AWS Access Key ID"),
    (re.compile(r"\b(?P<val>sk-ant-[A-Za-z0-9_-]{16,})\b"), "Anthropic API Key"),
    (re.compile(r"\b(?P<val>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"), "Stripe Secret Key"),
    (re.compile(r"\b(?P<val>sk-(?:proj-|live-)?[A-Za-z0-9_-]{16,})\b"), "API Secret Key (OpenAI / Stripe style)"),
    (re.compile(r"\b(?P<val>AIza[0-9A-Za-z_-]{35})\b"), "Google API Key"),
    (re.compile(r"\b(?P<val>xox[baprs]-[A-Za-z0-9-]{10,})\b"), "Slack Token"),
    (re.compile(r"\b(?P<val>npm_[A-Za-z0-9]{20,})\b"), "npm Access Token"),
    (re.compile(r"\b(?P<val>pypi-[A-Za-z0-9_-]{20,})\b"), "PyPI API Token"),
    (re.compile(r"\b(?P<val>hf_[A-Za-z0-9]{20,})\b"), "Hugging Face Token"),
    (re.compile(r"\b(?P<val>whsec_[A-Za-z0-9_-]{8,})\b"), "Webhook Signing Secret"),
    (re.compile(r"(?P<val>-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"), "Private Key Material"),
    (re.compile(r"(?i)postgres(?:ql)?://[^:\s/]+:(?P<val>[^@\s/]{6,})@"), "Database URI Password"),
]

# Context-aware generic assignment detector (must terminate at whitespace/EOL/comment, never before `(`)
GENERIC_ASSIGNMENT_RX = re.compile(
    r"(?i)\b(?:password|passwd|secret|api_key|access_token|auth_token|webhook_secret)\b\s*[:=]\s*"
    r"(?:['\"](?P<qval>[^'\"\s]{8,})['\"]|(?P<uval>[A-Za-z0-9_./+=-]{8,})(?=$|[\s,;#]))"
)
SAFE_VALUE_HINTS = (
    "os.environ", "os.getenv", "process.env", "env.", "settings.", "config.",
    "placeholder", "example", "changeme", "your_", "dummy", "localhost", "${", "{{",
)

RISKY_COMMIT_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\b(disable auth|skip auth|bypass auth|no[- ]?auth|allow all|0\.0\.0\.0/0)\b", re.IGNORECASE), "Authentication or access control weakened", "high"),
    (re.compile(r"\b(wip|temp|hack|quickfix|todo|fixme|bypass|workaround)\b", re.IGNORECASE), "Unreviewed shortcut language in commit", "medium"),
    (re.compile(r"\b(force|revert|hotfix|emergency|prod fix)\b", re.IGNORECASE), "High-urgency production change", "medium"),
]

SENSITIVE_FILENAME_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(^|/)\.env(\.[^/]+)?$", re.IGNORECASE), "Environment file committed to repository"),
    (re.compile(r"\.(pem|key|p12|pfx|jks)$", re.IGNORECASE), "Cryptographic key or certificate file committed"),
    (re.compile(r"(^|/)(id_rsa|id_ed25519|credentials\.json|service-account\.json)$", re.IGNORECASE), "Sensitive credential file committed"),
]

RISKY_PR_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\b(disable auth|skip check|bypass|no review|disable ssl|verify=false)\b", re.IGNORECASE), "PR weakens security or verification checks", "high"),
    (re.compile(r"\b(hotfix|emergency|quickfix|temp|hack|wip)\b", re.IGNORECASE), "Urgent or unfinished PR open against default branch", "medium"),
]

# Deterministic preview dataset used ONLY when running locally outside a Fly.io Sprite
DEMO_USER = {"login": "akuraposo", "name": "Agung Suryokusumo", "public_repos": 12}
DEMO_REPOS = [
    {
        "full_name": "akuraposo/loopclose",
        "private": False,
        "default_branch": "main",
        "open_issues_count": 0,
        "pushed_at": "2026-11-25T01:40:00Z",
        "language": "Python",
        "html_url": "https://github.com/akuraposo/loopclose",
        "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
    },
    {
        "full_name": "akuraposo/payments-worker",
        "private": True,
        "default_branch": "main",
        "open_issues_count": 3,
        "pushed_at": "2026-11-24T19:12:00Z",
        "language": "TypeScript",
        "html_url": "https://github.com/akuraposo/payments-worker",
        "security_and_analysis": {"secret_scanning": {"status": "disabled"}},
    },
    {
        "full_name": "akuraposo/internal-cli",
        "private": True,
        "default_branch": "main",
        "open_issues_count": 1,
        "pushed_at": "2026-11-22T08:45:00Z",
        "language": "Go",
        "html_url": "https://github.com/akuraposo/internal-cli",
        "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
    },
    {
        "full_name": "akuraposo/public-webhook-demo",
        "private": False,
        "default_branch": "main",
        "open_issues_count": 2,
        "pushed_at": "2026-11-23T14:20:00Z",
        "language": "JavaScript",
        "html_url": "https://github.com/akuraposo/public-webhook-demo",
        "security_and_analysis": {"secret_scanning": {"status": "disabled"}},
    },
]

DEMO_COMMITS: dict[str, list[dict[str, Any]]] = {
    "akuraposo/loopclose": [
        {"sha": "2fc54149a", "commit": {"message": "docs: add YouTube demo link to README and LAUNCH", "author": {"date": "2026-11-25T01:40:00Z"}}},
        {"sha": "fb76faa1c", "commit": {"message": "docs: update README with live demo URL and clean file table", "author": {"date": "2026-11-25T01:32:00Z"}}},
        {"sha": "67b5324e0", "commit": {"message": "chore: make loop.py cross-platform and refine .gitignore", "author": {"date": "2026-11-25T01:10:00Z"}}},
    ],
    "akuraposo/payments-worker": [
        {
            "sha": "a91c0f28b",
            "commit": {"message": "hotfix: quickfix webhook timeout retry", "author": {"date": "2026-11-24T19:12:00Z"}},
            "files": [{"filename": "src/webhook.ts", "patch": "+ const retryMs = 2500;\n+ const fallbackKey = 'sk-live-9f8e7d6c5b4a3210fedcba';"}],
        },
        {
            "sha": "8d21b4e11",
            "commit": {"message": "wip: disable auth check on staging health route", "author": {"date": "2026-11-24T17:04:00Z"}},
            "files": [{"filename": "src/routes/health.ts", "patch": "+ // TODO: re-enable auth middleware before prod"}],
        },
    ],
    "akuraposo/internal-cli": [
        {"sha": "e4419d17f", "commit": {"message": "feat: add structured JSON output flag", "author": {"date": "2026-11-22T08:45:00Z"}}},
    ],
    "akuraposo/public-webhook-demo": [
        {
            "sha": "c309ab12d",
            "commit": {"message": "chore: add local config sample", "author": {"date": "2026-11-23T14:20:00Z"}},
            "files": [{"filename": ".env.production", "patch": "+ STRIPE_WEBHOOK_SECRET=whsec_demo"}],
        },
    ],
}

DEMO_PRS: dict[str, list[dict[str, Any]]] = {
    "akuraposo/loopclose": [],
    "akuraposo/payments-worker": [
        {
            "number": 42,
            "title": "hotfix: bypass webhook signature check for legacy partner",
            "body": "Temporary workaround so legacy partner callbacks succeed before Friday.",
            "draft": False,
            "created_at": "2026-11-24T18:10:00Z",
            "html_url": "https://github.com/akuraposo/payments-worker/pull/42",
            "user": {"login": "akuraposo"},
            "requested_reviewers": [],
        }
    ],
    "akuraposo/internal-cli": [
        {
            "number": 11,
            "title": "feat: add YAML config exporter",
            "body": "Clean additive change with unit tests.",
            "draft": True,
            "created_at": "2026-11-20T09:00:00Z",
            "html_url": "https://github.com/akuraposo/internal-cli/pull/11",
            "user": {"login": "akuraposo"},
            "requested_reviewers": [{"login": "reviewer-bot"}],
        }
    ],
    "akuraposo/public-webhook-demo": [],
}

LAST_AUDIT: dict[str, Any] | None = None
AUDIT_HISTORY: list[dict[str, Any]] = []
REMEDIATED_ISSUES: dict[str, dict[str, Any]] = {}
PREVIEW_REMEDIATED_ISSUES: dict[str, dict[str, Any]] = {}
AUDITED_REPOS: set[str] = set()


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact_secret(text: str) -> str:
    """Mask middle characters of a matched secret value so it is never exposed."""
    clean = text.strip()
    if len(clean) <= 12:
        return "***REDACTED***"
    return f"{clean[:4]}…{clean[-4:]}"


def inspect_zero_secrets() -> dict[str, Any]:
    """Prove that no GitHub or API credentials exist inside this Sprite environment."""
    flagged_env: set[str] = set()
    for k, v in os.environ.items():
        if k in ("SPRITES_GATEWAY_BASE", "SPRITES_OPENROUTER_GATEWAY", "GHOSTWATCH_DASHBOARD_TOKEN"):
            continue
        if SECRET_ENV_PATTERNS.search(k):
            flagged_env.add(k)
            continue
        # Also scan values in-memory against high-confidence provider prefixes (never returning raw values)
        if v and any(rx.search(v) for rx, _ in PROVIDER_SECRET_PATTERNS):
            flagged_env.add(f"{k} (value matched provider token pattern)")
    flagged_sorted = sorted(flagged_env)
    checked_files: list[dict[str, Any]] = []
    present_cred_files: list[str] = []
    for candidate in CREDENTIAL_FILE_CANDIDATES:
        exists = candidate.exists()
        display_name = str(candidate.relative_to(ROOT)) if candidate.is_relative_to(ROOT) else f"~/{candidate.relative_to(Path.home())}" if candidate.is_relative_to(Path.home()) else str(candidate)
        checked_files.append({"path": display_name, "present": exists})
        if exists:
            present_cred_files.append(display_name)

    dot_env_exists = (ROOT / ".env").exists()
    return {
        "hostname": socket.gethostname(),
        "gateway_base": GATEWAY_BASE,
        "auth_header_sent_by_agent": None,
        "secret_env_vars_found": len(flagged_sorted),
        "secret_env_names": flagged_sorted,
        "dotenv_file_present": dot_env_exists,
        "credential_files_checked": checked_files,
        "credential_files_found": present_cred_files,
        "zero_credential_verified": len(flagged_sorted) == 0 and len(present_cred_files) == 0,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def gateway_request(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[Any, dict[str, Any]]:
    """Call the Fly.io Sprites Connector Gateway with ZERO Authorization headers."""
    url = f"{GATEWAY_BASE}/{path.lstrip('/')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "GhostWatch-Sprite-Agent/2.0",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    started = dt.datetime.now(dt.timezone.utc)
    with urllib.request.urlopen(req, timeout=8) as resp:
        raw = resp.read().decode("utf-8")
        elapsed_ms = int((dt.datetime.now(dt.timezone.utc) - started).total_seconds() * 1000)
        trace = {
            "method": method.upper(),
            "url": url,
            "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
            "status": resp.status,
            "latency_ms": elapsed_ms,
            "mode": "live-sprites-connector",
        }
        return (json.loads(raw) if raw else {}), trace


def gateway_get(path: str) -> tuple[Any, dict[str, Any]]:
    return gateway_request("GET", path)


def gateway_post(path: str, body: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    return gateway_request("POST", path, body=body)


def _scan_text_for_all_secrets(text: str) -> list[tuple[str, str]]:
    """Return ALL distinct (label, redacted_val) secret hits using provider prefixes + entropy checks."""
    hits: list[tuple[str, str]] = []
    seen_vals: set[str] = set()

    for rx, label in PROVIDER_SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group("val")
            if val not in seen_vals:
                seen_vals.add(val)
                hits.append((label, redact_secret(val)))

    for m in GENERIC_ASSIGNMENT_RX.finditer(text):
        qval = (m.group("qval") or "").strip()
        uval = (m.group("uval") or "").strip()
        val = qval or uval
        is_quoted = bool(qval)
        if not val or val in seen_vals:
            continue
        low = val.lower()
        if any(hint in low for hint in SAFE_VALUE_HINTS):
            continue
        # Only skip dotted code member expressions and pure alphabetic/underscore code identifiers for UNQUOTED values
        if not is_quoted:
            if "." in val and not val.startswith("eyJ"):
                continue
            if re.fullmatch(r"[A-Za-z_]+", val):
                continue
        if _shannon_entropy(val) < 3.0:
            continue
        seen_vals.add(val)
        hits.append(("Hardcoded credential assignment", redact_secret(val)))

    return hits


def _scan_text_for_secrets(text: str) -> tuple[str, str] | None:
    hits = _scan_text_for_all_secrets(text)
    return hits[0] if hits else None


def analyze_commits(repo_name: str, commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for c in commits[:6]:
        full_sha = c.get("sha") or ""
        sha = full_sha[:7]
        full_msg = c.get("commit", {}).get("message") or ""
        first_line = full_msg.splitlines()[0] if full_msg else "(empty commit message)"
        date = c.get("commit", {}).get("author", {}).get("date", "")
        html_url = c.get("html_url") or f"https://github.com/{repo_name}/commit/{full_sha or sha}"

        # 1. Secret scan on full commit message (do NOT skip file/patch scanning!)
        msg_secrets = _scan_text_for_all_secrets(full_msg)
        for idx, (label, snippet) in enumerate(msg_secrets):
            findings.append({
                "id": f"commit-secret:{repo_name}:{sha}:{idx}",
                "category": "secret",
                "repo": repo_name,
                "ref": sha,
                "sha": sha,
                "message": first_line,
                "evidence": f"Detected {label} ({snippet}) in commit message",
                "date": date,
                "severity": "high",
                "reason": f"Possible leaked {label} in commit message",
                "url": html_url,
            })

        # 2. Scan commit files & patches (emit ALL secret hits per patch)
        patch_flagged = False
        for fobj in c.get("files") or []:
            fname = fobj.get("filename") or ""
            for rx, reason in SENSITIVE_FILENAME_PATTERNS:
                if rx.search(fname):
                    findings.append({
                        "id": f"commit-file:{repo_name}:{sha}:{fname}",
                        "category": "secret",
                        "repo": repo_name,
                        "ref": sha,
                        "sha": sha,
                        "message": f"{first_line} ({fname})",
                        "evidence": f"Sensitive file modified: {fname}",
                        "date": date,
                        "severity": "high",
                        "reason": reason,
                        "url": html_url,
                    })
                    patch_flagged = True
                    break
            patch = fobj.get("patch") or ""
            added_lines = "\n".join(
                line[1:] for line in patch.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            )
            for idx, (label, snippet) in enumerate(_scan_text_for_all_secrets(added_lines)):
                findings.append({
                    "id": f"commit-patch:{repo_name}:{sha}:{fname}:{idx}",
                    "category": "secret",
                    "repo": repo_name,
                    "ref": sha,
                    "sha": sha,
                    "message": f"{first_line} ({fname})",
                    "evidence": f"Redacted match in diff: {snippet}",
                    "date": date,
                    "severity": "high",
                    "reason": f"Possible leaked {label} in commit diff",
                    "url": html_url,
                })
                patch_flagged = True

        if msg_secrets or patch_flagged:
            continue

        # 3. Risky commit message heuristics
        for rx, reason, severity in RISKY_COMMIT_PATTERNS:
            if rx.search(first_line):
                findings.append({
                    "id": f"commit-msg:{repo_name}:{sha}",
                    "category": "commit",
                    "repo": repo_name,
                    "ref": sha,
                    "sha": sha,
                    "message": first_line,
                    "evidence": "Matched commit risk policy",
                    "date": date,
                    "severity": severity,
                    "reason": reason,
                    "url": html_url,
                })
                break
    return findings


def analyze_pull_requests(repo_name: str, prs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pr in prs[:5]:
        num = pr.get("number")
        title = pr.get("title") or "(untitled PR)"
        body = pr.get("body") or ""
        combined = f"{title}\n{body}"
        created_at = pr.get("created_at", "")
        url = pr.get("html_url") or f"https://github.com/{repo_name}/pull/{num}"
        reviewers = pr.get("requested_reviewers") or []

        pr_secrets = _scan_text_for_all_secrets(combined)
        for idx, (label, snippet) in enumerate(pr_secrets):
            findings.append({
                "id": f"pr-secret:{repo_name}:{num}:{idx}",
                "category": "pr",
                "repo": repo_name,
                "ref": f"PR #{num}",
                "sha": f"#{num}",
                "message": title,
                "evidence": f"Detected {label} ({snippet}) in PR description",
                "date": created_at,
                "severity": "high",
                "reason": f"Possible leaked {label} in open pull request",
                "url": url,
            })
        if pr_secrets:
            continue

        matched_policy = False
        for rx, reason, severity in RISKY_PR_PATTERNS:
            if rx.search(combined):
                findings.append({
                    "id": f"pr-risk:{repo_name}:{num}",
                    "category": "pr",
                    "repo": repo_name,
                    "ref": f"PR #{num}",
                    "sha": f"#{num}",
                    "message": title,
                    "evidence": "No reviewers assigned" if not reviewers else f"{len(reviewers)} reviewer(s) requested",
                    "date": created_at,
                    "severity": severity,
                    "reason": reason,
                    "url": url,
                })
                matched_policy = True
                break

        if not matched_policy and not pr.get("draft") and not reviewers:
            findings.append({
                "id": f"pr-unreviewed:{repo_name}:{num}",
                "category": "pr",
                "repo": repo_name,
                "ref": f"PR #{num}",
                "sha": f"#{num}",
                "message": title,
                "evidence": "Open non-draft PR has 0 requested reviewers",
                "date": created_at,
                "severity": "low",
                "reason": "Open pull request without assigned reviewer",
                "url": url,
            })
    return findings


def analyze_repo_posture(repo: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    fn = repo["full_name"]
    is_public = not bool(repo.get("private"))
    sec = repo.get("security_and_analysis") or {}
    secret_scan_status = (sec.get("secret_scanning") or {}).get("status")
    if is_public and secret_scan_status == "disabled":
        findings.append({
            "id": f"config-secret-scan:{fn}",
            "category": "config",
            "repo": fn,
            "ref": repo.get("default_branch", "main"),
            "sha": repo.get("default_branch", "main"),
            "message": "GitHub Secret Scanning is disabled on public repository",
            "evidence": "visibility=public, secret_scanning=disabled",
            "date": repo.get("pushed_at", ""),
            "severity": "medium",
            "reason": "Public repository lacks GitHub secret scanning protection",
            "url": repo.get("html_url", ""),
        })
    return findings


def _fetch_repo_activity(r: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Fetch recent commits, diffs, and open PRs for one repository."""
    fn = r["full_name"]
    local_traces: list[dict[str, Any]] = []
    local_warnings: list[str] = []
    commit_list: list[dict[str, Any]] = []
    pr_list: list[dict[str, Any]] = []

    try:
        cs, t_c = gateway_get(f"repos/{fn}/commits?per_page=5")
        local_traces.append(t_c)
        commit_list = cs if isinstance(cs, list) else []
        for commit_item in commit_list[:MAX_COMMIT_DIFFS_PER_REPO]:
            sha = commit_item.get("sha")
            if not sha:
                continue
            try:
                detail, t_d = gateway_get(f"repos/{fn}/commits/{sha}")
                local_traces.append(t_d)
                if isinstance(detail, dict) and detail.get("files"):
                    commit_item["files"] = detail["files"]
            except urllib.error.HTTPError as exc:
                local_traces.append({
                    "method": "GET",
                    "url": f"{GATEWAY_BASE}/repos/{fn}/commits/{sha}",
                    "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                    "status": exc.code,
                    "latency_ms": 0,
                    "mode": "gateway-error",
                })
                local_warnings.append(f"commit diff HTTP {exc.code}")
            except Exception as exc:
                local_warnings.append(f"commit diff failed: {exc}")
    except urllib.error.HTTPError as exc:
        local_traces.append({
            "method": "GET",
            "url": f"{GATEWAY_BASE}/repos/{fn}/commits?per_page=5",
            "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
            "status": exc.code,
            "latency_ms": 0,
            "mode": "gateway-error",
        })
        local_warnings.append("empty repository (HTTP 409)" if exc.code == 409 else f"commits fetch HTTP {exc.code}")
        commit_list = []
    except Exception as exc:
        local_warnings.append(f"commits fetch failed: {exc}")
        commit_list = []

    try:
        prs, t_p = gateway_get(f"repos/{fn}/pulls?state=open&per_page=5")
        local_traces.append(t_p)
        pr_list = prs if isinstance(prs, list) else []
    except urllib.error.HTTPError as exc:
        local_traces.append({
            "method": "GET",
            "url": f"{GATEWAY_BASE}/repos/{fn}/pulls?state=open&per_page=5",
            "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
            "status": exc.code,
            "latency_ms": 0,
            "mode": "gateway-error",
        })
        local_warnings.append(f"pulls fetch HTTP {exc.code}")
        pr_list = []
    except Exception as exc:
        local_warnings.append(f"pulls fetch failed: {exc}")
        pr_list = []

    return fn, commit_list, pr_list, local_traces, local_warnings


def run_audit(force_demo: bool = False) -> dict[str, Any]:
    traces: list[dict[str, Any]] = []
    mode = "live-sprites-connector"
    fallback_reason = None
    commits_by_repo: dict[str, list[dict[str, Any]]] = {}
    prs_by_repo: dict[str, list[dict[str, Any]]] = {}

    gateway_error: dict[str, Any] | None = None
    repo_warnings: dict[str, list[str]] = {}

    if not force_demo:
        try:
            user, t_user = gateway_get("user")
            traces.append(t_user)
            repos, t_repos = gateway_get("user/repos?sort=pushed&per_page=8")
            traces.append(t_repos)
            if not isinstance(repos, list):
                raise ValueError("Unexpected non-list response from /user/repos")
            target_repos = repos[:MAX_REPOS]
            if target_repos:
                with ThreadPoolExecutor(max_workers=min(6, len(target_repos))) as pool:
                    for fn, cs, prs, r_traces, r_warns in pool.map(_fetch_repo_activity, target_repos):
                        commits_by_repo[fn] = cs
                        prs_by_repo[fn] = prs
                        traces.extend(r_traces)
                        if r_warns:
                            repo_warnings[fn] = r_warns
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            mode = "gateway-error"
            fallback_reason = f"Sprites Gateway returned HTTP {exc.code}: {exc.reason}"
            gateway_error = {"status": exc.code, "reason": str(exc.reason), "body": err_body}
            traces.append({
                "method": "GET",
                "url": getattr(exc, "url", f"{GATEWAY_BASE}/user"),
                "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                "status": exc.code,
                "latency_ms": 0,
                "mode": "gateway-error",
            })
            user = {"login": "unknown"}
            repos = []
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            mode = "local-preview"
            fallback_reason = f"Sprites Gateway unreachable outside Fly.io Sprite ({exc})"
            user = DEMO_USER
            repos = DEMO_REPOS
            commits_by_repo = DEMO_COMMITS
            prs_by_repo = DEMO_PRS
    else:
        mode = "local-preview"
        fallback_reason = "Preview mode requested"
        user = DEMO_USER
        repos = DEMO_REPOS
        commits_by_repo = DEMO_COMMITS
        prs_by_repo = DEMO_PRS

    if mode == "local-preview":
        traces = [
            {
                "method": "GET",
                "url": f"{GATEWAY_BASE}/user",
                "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                "status": 200,
                "latency_ms": 38,
                "mode": "local-preview",
            },
            {
                "method": "GET",
                "url": f"{GATEWAY_BASE}/user/repos?sort=pushed&per_page=8",
                "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                "status": 200,
                "latency_ms": 64,
                "mode": "local-preview",
            },
            {
                "method": "GET",
                "url": f"{GATEWAY_BASE}/repos/akuraposo/payments-worker/commits/a91c0f28b",
                "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                "status": 200,
                "latency_ms": 51,
                "mode": "local-preview",
            },
            {
                "method": "GET",
                "url": f"{GATEWAY_BASE}/repos/akuraposo/payments-worker/pulls?state=open&per_page=5",
                "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                "status": 200,
                "latency_ms": 47,
                "mode": "local-preview",
            },
        ]

    all_findings: list[dict[str, Any]] = []
    repo_reports = []
    total_prs_checked = 0
    total_commits_checked = 0

    for r in repos[:MAX_REPOS]:
        fn = r["full_name"]
        cs = commits_by_repo.get(fn, [])
        prs = prs_by_repo.get(fn, [])
        total_commits_checked += len(cs)
        total_prs_checked += len(prs)

        rf = (
            analyze_commits(fn, cs)
            + analyze_pull_requests(fn, prs)
            + analyze_repo_posture(r)
        )
        # Attach remediation state strictly matching the current audit mode
        rem_store = PREVIEW_REMEDIATED_ISSUES if mode == "local-preview" else REMEDIATED_ISSUES
        with STATE_LOCK:
            for item in rf:
                if item["id"] in rem_store:
                    item["remediation_issue"] = rem_store[item["id"]]

        all_findings.extend(rf)
        high_cnt = sum(1 for f in rf if f["severity"] == "high")
        med_cnt = sum(1 for f in rf if f["severity"] == "medium")
        low_cnt = sum(1 for f in rf if f["severity"] == "low")
        score = max(0, 100 - high_cnt * 28 - med_cnt * 10 - low_cnt * 4)
        warns = repo_warnings.get(fn, [])
        repo_reports.append({
            "full_name": fn,
            "private": bool(r.get("private")),
            "language": r.get("language") or "Mixed",
            "pushed_at": r.get("pushed_at", ""),
            "commits_checked": len(cs),
            "prs_checked": len(prs),
            "findings_count": len(rf),
            "high_count": high_cnt,
            "medium_count": med_cnt,
            "health_score": score,
            "status": "attention" if high_cnt else ("review" if (med_cnt or warns) else "clean"),
            "scan_warning": "; ".join(warns) if warns else None,
            "html_url": r.get("html_url", ""),
        })

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    all_findings.sort(key=lambda x: (severity_rank.get(x["severity"], 9), x["repo"]))

    if repo_reports:
        avg_score = sum(r["health_score"] for r in repo_reports) / len(repo_reports)
        worst_score = min(r["health_score"] for r in repo_reports)
        # Risk-weighted overall score: a single breached repo pulls the headline score down
        overall = round(avg_score * 0.65 + worst_score * 0.35)
    else:
        overall = 0
    scanned_at = dt.datetime.now(dt.timezone.utc).isoformat()
    with STATE_LOCK:
        previous_score = AUDIT_HISTORY[-1]["overall_score"] if AUDIT_HISTORY else None
        score_delta = (overall - previous_score) if previous_score is not None else 0
        summary = {
            "repos_audited": len(repo_reports),
            "commits_checked": total_commits_checked,
            "prs_checked": total_prs_checked,
            "high_findings": sum(1 for f in all_findings if f["severity"] == "high"),
            "medium_findings": sum(1 for f in all_findings if f["severity"] == "medium"),
            "low_findings": sum(1 for f in all_findings if f["severity"] == "low"),
            "score_delta": score_delta,
        }
        AUDIT_HISTORY.append({
            "scanned_at": scanned_at,
            "mode": mode,
            "overall_score": overall,
            "findings_count": len(all_findings),
            "high_findings": summary["high_findings"],
        })
        if len(AUDIT_HISTORY) > 20:
            del AUDIT_HISTORY[:-20]
        if mode == "live-sprites-connector":
            AUDITED_REPOS.update(r["full_name"] for r in repo_reports)
        save_persisted_state_locked()
        recent_history = list(AUDIT_HISTORY[-8:])

    return {
        "mode": mode,
        "fallback_reason": fallback_reason,
        "gateway_error": gateway_error,
        "scanned_at": scanned_at,
        "account": user.get("login", "unknown"),
        "overall_score": overall,
        "summary": summary,
        "repos": repo_reports,
        "findings": all_findings,
        "gateway_traces": traces,
        "zero_secrets": inspect_zero_secrets(),
        "history": recent_history,
    }


def create_remediation_issue(payload: dict[str, Any]) -> dict[str, Any]:
    """Open a GitHub Security Alert Issue via Sprites Gateway (zero tokens in Sprite)."""
    repo = str(payload.get("repo") or "").strip()
    finding_id = str(payload.get("finding_id") or "").strip()
    force_demo = bool(payload.get("demo"))

    with STATE_LOCK:
        last_audit = LAST_AUDIT
        audited_repos = set(AUDITED_REPOS) | {r["full_name"] for r in (last_audit or {}).get("repos", [])}
        last_mode = (last_audit or {}).get("mode")

    if force_demo and last_mode == "live-sprites-connector":
        raise ValueError("Cannot create simulated preview issue during a live connector audit")

    # Resolve verified finding metadata from LAST_AUDIT when available
    verified_finding = None
    if finding_id and last_audit:
        for item in last_audit.get("findings", []):
            if item.get("id") == finding_id:
                verified_finding = item
                break

    if verified_finding is not None:
        repo = str(verified_finding.get("repo") or repo).strip()
        reason = str(verified_finding.get("reason") or "Security finding detected").strip()
        ref = str(verified_finding.get("ref") or "main").strip()
        severity = str(verified_finding.get("severity") or "medium").upper()
        evidence = str(verified_finding.get("evidence") or "").strip()
        message = str(verified_finding.get("message") or "").strip()
    else:
        reason = str(payload.get("reason") or "Security finding detected").strip()[:200]
        ref = str(payload.get("ref") or "main").strip()[:80]
        sev_raw = str(payload.get("severity") or "medium").strip().upper()
        severity = sev_raw if sev_raw in ("HIGH", "MEDIUM", "LOW") else "MEDIUM"
        evidence = str(payload.get("evidence") or "").strip()[:500]
        message = str(payload.get("message") or "").strip()[:300]

    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo):
        raise ValueError("Invalid repository name format (expected owner/repo)")

    # Keep preview remediations isolated from live REMEDIATED_ISSUES
    rem_store = PREVIEW_REMEDIATED_ISSUES if force_demo else REMEDIATED_ISSUES
    if finding_id:
        with STATE_LOCK:
            existing = rem_store.get(finding_id)
        if existing:
            return {
                "mode": existing["mode"],
                "issue_number": existing["issue_number"],
                "html_url": existing["html_url"],
                "title": f"[GhostWatch {severity}] {reason} ({ref})",
                "deduplicated": True,
                "trace": None,
            }

    if force_demo:
        allowed_demo_repos = {r["full_name"] for r in DEMO_REPOS} | audited_repos
        if repo not in allowed_demo_repos:
            raise ValueError(f"Repository '{repo}' is not in the preview repository set")
    else:
        if not audited_repos:
            raise ValueError("No audited repositories recorded yet; run /api/scan before opening issues")
        if repo not in audited_repos:
            raise ValueError(f"Repository '{repo}' is not in the audited repository set")

    issue_title = f"[GhostWatch {severity}] {reason} ({ref})"
    issue_body = (
        f"## GhostWatch Automated Security Alert\n\n"
        f"- **Repository:** `{repo}`\n"
        f"- **Reference:** `{ref}`\n"
        f"- **Severity:** `{severity}`\n"
        f"- **Summary:** {message}\n"
        f"- **Evidence:** {evidence}\n\n"
        f"---\n"
        f"_Opened via Fly.io Sprites Connector Gateway with zero credentials stored in the Sprite._"
    )

    body = {"title": issue_title, "body": issue_body}
    if force_demo:
        with STATE_LOCK:
            sim_num = 100 + len(PREVIEW_REMEDIATED_ISSUES) + 1
        result = {
            "mode": "local-preview",
            "issue_number": sim_num,
            "html_url": f"https://github.com/{repo}/issues/{sim_num}",
            "title": issue_title,
            "trace": {
                "method": "POST",
                "url": f"{GATEWAY_BASE}/repos/{repo}/issues",
                "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                "status": 201,
                "latency_ms": 54,
                "mode": "local-preview",
            },
        }
    else:
        try:
            resp, trace = gateway_post(f"repos/{repo}/issues", body)
            result = {
                "mode": "live-sprites-connector",
                "issue_number": resp.get("number"),
                "html_url": resp.get("html_url", f"https://github.com/{repo}/issues"),
                "title": issue_title,
                "trace": trace,
            }
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            err_trace = {
                "method": "POST",
                "url": f"{GATEWAY_BASE}/repos/{repo}/issues",
                "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                "status": exc.code,
                "latency_ms": 0,
                "mode": "gateway-error",
            }
            raise GatewayHTTPError(
                exc.code,
                f"Sprites Gateway rejected issue creation with HTTP {exc.code}: {exc.reason}"
                + (f" ({err_body})" if err_body else ""),
                err_trace,
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            with STATE_LOCK:
                sim_num = 100 + len(PREVIEW_REMEDIATED_ISSUES) + 1
            result = {
                "mode": "local-preview",
                "issue_number": sim_num,
                "html_url": f"https://github.com/{repo}/issues/{sim_num}",
                "title": issue_title,
                "trace": {
                    "method": "POST",
                    "url": f"{GATEWAY_BASE}/repos/{repo}/issues",
                    "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                    "status": 201,
                    "latency_ms": 54,
                    "mode": "local-preview",
                },
            }
            rem_store = PREVIEW_REMEDIATED_ISSUES

    if finding_id:
        with STATE_LOCK:
            rem_store[finding_id] = {
                "issue_number": result["issue_number"],
                "html_url": result["html_url"],
                "mode": result["mode"],
            }
            if rem_store is REMEDIATED_ISSUES:
                save_persisted_state_locked()
    return result


def save_persisted_state_locked():
    """Persist scan history, remediated issues & audited repos to Sprite disk (caller holds STATE_LOCK)."""
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "audit_history": AUDIT_HISTORY[-20:],
                    "remediated_issues": REMEDIATED_ISSUES,
                    "audited_repos": sorted(AUDITED_REPOS),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        tmp.replace(STATE_FILE)
    except OSError:
        pass


def load_persisted_state():
    """Restore persisted scan history, remediated issues & audited repos on Sprite restart."""
    if not STATE_FILE.exists():
        return
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        with STATE_LOCK:
            hist = data.get("audit_history")
            if isinstance(hist, list):
                AUDIT_HISTORY.clear()
                AUDIT_HISTORY.extend(hist[-20:])
            rem = data.get("remediated_issues")
            if isinstance(rem, dict):
                REMEDIATED_ISSUES.clear()
                REMEDIATED_ISSUES.update(rem)
            ar = data.get("audited_repos")
            if isinstance(ar, list):
                AUDITED_REPOS.clear()
                AUDITED_REPOS.update(str(x) for x in ar if isinstance(x, str))
    except Exception:
        pass


def _normalize_steps(raw_steps: Any) -> list[str]:
    if isinstance(raw_steps, list):
        return [str(s).strip() for s in raw_steps if str(s).strip()][:4]
    if isinstance(raw_steps, str) and raw_steps.strip():
        return [raw_steps.strip()]
    return []


def render_sarif_report(audit: dict[str, Any]) -> dict[str, Any]:
    """Export findings as SARIF 2.1.0 for GitHub Code Scanning / VS Code / CI."""
    level_map = {"high": "error", "medium": "warning", "low": "note"}
    results = []
    for f in audit.get("findings", []):
        results.append({
            "ruleId": f"ghostwatch/{f.get('category', 'security')}",
            "level": level_map.get(f.get("severity", "medium"), "warning"),
            "message": {"text": f"{f.get('reason', '')}: {f.get('evidence', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"{f.get('repo', 'repo')}@{f.get('ref', 'main')}"},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GhostWatch",
                    "version": "2.1.0",
                    "informationUri": "https://github.com/akuraposo/ghostwatch",
                }
            },
            "results": results,
        }],
    }


def _strip_json_fences(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def triage_finding(payload: dict[str, Any]) -> dict[str, Any]:
    """Generate contextual root-cause & fix guidance via OpenRouter Connector, Ollama, or local playbook."""
    repo = str(payload.get("repo") or "").strip()
    category = str(payload.get("category") or "security").strip()
    severity = str(payload.get("severity") or "medium").strip().lower()
    reason = str(payload.get("reason") or "Security finding").strip()
    message = str(payload.get("message") or "").strip()
    evidence = str(payload.get("evidence") or "").strip()

    prompt = (
        "You are GhostWatch, a concise security remediation agent running inside a Fly.io Sprite. "
        "Return STRICT JSON with keys: impact (1 sentence), fix_steps (array of 2-3 concrete steps), "
        "verification (1 command or check to verify the fix).\n"
        f"Finding: repo={repo}, category={category}, severity={severity}, reason={reason}, "
        f"message={message}, evidence={evidence}"
    )

    # 1. Try Fly.io Sprites OpenRouter Connector (zero API keys in Sprite)
    or_url = f"{OPENROUTER_GW}/v1/chat/completions"
    try:
        req = urllib.request.Request(
            or_url,
            data=json.dumps({
                "model": TRIAGE_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            }).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "GhostWatch/2.1"},
            method="POST",
        )
        t0 = dt.datetime.now(dt.timezone.utc)
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
            ms = int((dt.datetime.now(dt.timezone.utc) - t0).total_seconds() * 1000)
        parsed = json.loads(_strip_json_fences(raw["choices"][0]["message"]["content"]))
        return {
            "engine": "sprites-openrouter-connector",
            "model": TRIAGE_MODEL,
            "impact": str(parsed.get("impact", "")),
            "fix_steps": _normalize_steps(parsed.get("fix_steps")),
            "verification": str(parsed.get("verification", "")),
            "trace": {
                "method": "POST",
                "url": or_url,
                "authorization_header": "(none — injected by Fly.io Sprites Gateway)",
                "status": 200,
                "latency_ms": ms,
                "mode": "live-sprites-connector",
            },
        }
    except Exception:
        pass

    # 2. Try local Ollama inside the Sprite (zero external keys)
    try:
        req = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        t0 = dt.datetime.now(dt.timezone.utc)
        with urllib.request.urlopen(req, timeout=6) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
            ms = int((dt.datetime.now(dt.timezone.utc) - t0).total_seconds() * 1000)
        parsed = json.loads(_strip_json_fences(raw.get("response", "{}")))
        return {
            "engine": "local-ollama",
            "model": OLLAMA_MODEL,
            "impact": str(parsed.get("impact", "")),
            "fix_steps": _normalize_steps(parsed.get("fix_steps")),
            "verification": str(parsed.get("verification", "")),
            "trace": None,
        }
    except Exception:
        pass

    # 3. Transparent deterministic security playbook fallback (never fabricates a 200 gateway trace)
    if category == "secret":
        impact = f"Exposed credential in {repo} can be replayed immediately by anyone with repository read access."
        steps = [
            "Revoke and rotate the exposed secret at the provider dashboard immediately.",
            "Remove the secret from source and rewrite git history or force-push a clean commit.",
            "Move the credential behind a Fly.io Sprites Connector so zero tokens live in code or .env.",
        ]
        verify = "Re-run GhostWatch /api/scan and confirm high-severity secret findings drop to 0."
    elif category == "pr":
        impact = f"Unreviewed or weakened security check in {repo} could merge directly into the default branch."
        steps = [
            "Assign at least one code reviewer and require passing CI checks before merge.",
            "Restore any bypassed authentication, TLS verification, or test assertions in the PR.",
        ]
        verify = "Confirm GitHub branch protection requires 1 approving review and green checks."
    else:
        impact = f"Security posture gap in {repo} increases blast radius if a secret or regression is pushed."
        steps = [
            "Enable GitHub Secret Scanning and Push Protection in Repository Settings -> Code security.",
            "Audit recent commits for shortcut flags or weakened authentication routes.",
        ]
        verify = "Run GhostWatch /api/scan and verify repository health score returns to 100/100."

    return {
        "engine": "local-playbook",
        "model": "deterministic-playbook",
        "impact": impact,
        "fix_steps": steps,
        "verification": verify,
        "trace": None,
    }


def render_markdown_report(audit: dict[str, Any]) -> str:
    zs = audit["zero_secrets"]
    s = audit["summary"]
    lines = [
        f"# GhostWatch Security Audit Report",
        "",
        f"- **Account:** `@{audit['account']}`",
        f"- **Scanned At:** `{audit['scanned_at']}`",
        f"- **Mode:** `{audit['mode']}`",
        f"- **Overall Health Score:** **{audit['overall_score']}/100**",
        f"- **Zero-Credential Proof:** {'VERIFIED' if zs['zero_credential_verified'] else 'WARNING'} (`{zs['secret_env_vars_found']}` secret env vars, `{len(zs['credential_files_found'])}` credential files)",
        f"- **Coverage:** {s['repos_audited']} repos, {s['commits_checked']} commits, {s['prs_checked']} open PRs",
        "",
        "## Repository Ledger",
        "",
        "| Repository | Visibility | Commits | Open PRs | Score | Status |",
        "| --- | --- | ---: | ---: | ---: | --- |",
    ]
    for r in audit["repos"]:
        vis = "Private" if r["private"] else "Public"
        lines.append(
            f"| `{r['full_name']}` | {vis} | {r['commits_checked']} | {r['prs_checked']} | {r['health_score']} | {r['status']} |"
        )
    lines.extend(["", "## Findings", ""])
    if not audit["findings"]:
        lines.append("No risky patterns or leaked secrets detected.")
    else:
        for f in audit["findings"]:
            lines.append(
                f"- **[{f['severity'].upper()}]** `{f['repo']}` (`{f['ref']}`, `{f['category']}`): {f['reason']} — {f['evidence']}"
            )
    lines.append("")
    return "\n".join(lines)


class Handler(BaseHTTPRequestHandler):
    def _send_bytes(self, body: bytes, content_type: str, status: int = 200, extra_headers: dict[str, str] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: Any, status: int = 200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status=status)

    def _send_html(self, path: Path):
        self._send_bytes(path.read_bytes(), "text/html; charset=utf-8", status=200)

    def _check_auth(self) -> bool:
        if not DASHBOARD_TOKEN:
            return True
        auth = self.headers.get("Authorization", "")
        token_hdr = self.headers.get("X-GhostWatch-Token", "")
        expected_bearer = f"Bearer {DASHBOARD_TOKEN}"
        if hmac.compare_digest(auth, expected_bearer) or hmac.compare_digest(token_hdr, DASHBOARD_TOKEN):
            return True
        self._send_json({"error": "Unauthorized: set X-GhostWatch-Token or Bearer token"}, status=401)
        return False

    def _read_json_post(self) -> dict[str, Any] | None:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._send_json({"error": "Content-Type must be application/json"}, status=415)
            return None
        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        if origin is not None:
            parsed_origin = urllib.parse.urlsplit(origin.strip())
            if origin.strip().lower() == "null" or not parsed_origin.netloc or (host and parsed_origin.netloc != host):
                self._send_json({"error": "Cross-origin or null-origin POST rejected"}, status=403)
                return None
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except ValueError:
            self._send_json({"error": "Invalid Content-Length header"}, status=400)
            return None
        if length < 0:
            self._send_json({"error": "Negative Content-Length header"}, status=400)
            return None
        if length > MAX_POST_BYTES:
            self._send_json({"error": f"Payload exceeds {MAX_POST_BYTES} byte limit"}, status=413)
            return None
        try:
            raw = self.rfile.read(length).decode("utf-8") if length else ""
        except UnicodeDecodeError:
            self._send_json({"error": "Request body must be valid UTF-8"}, status=400)
            return None
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            self._send_json({"error": f"Malformed JSON body: {exc.msg}"}, status=400)
            return None
        if not isinstance(data, dict):
            self._send_json({"error": "JSON body must be an object"}, status=400)
            return None
        return data

    def do_GET(self):
        global LAST_AUDIT
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._send_html(STATIC_DIR / "index.html")
            return
        if not self._check_auth():
            return

        if path == "/api/scan":
            force_demo = qs.get("demo", ["0"])[0] == "1"
            audit = run_audit(force_demo=force_demo)
            with STATE_LOCK:
                LAST_AUDIT = audit
            self._send_json(audit)
        elif path == "/api/env-proof":
            self._send_json(inspect_zero_secrets())
        elif path == "/api/history":
            with STATE_LOCK:
                hist = list(AUDIT_HISTORY)
            self._send_json({"history": hist})
        elif path == "/api/report.md":
            with STATE_LOCK:
                audit = LAST_AUDIT
            if audit is None:
                audit = run_audit(force_demo=qs.get("demo", ["0"])[0] == "1")
                with STATE_LOCK:
                    LAST_AUDIT = audit
            md = render_markdown_report(audit).encode("utf-8")
            self._send_bytes(
                md,
                "text/markdown; charset=utf-8",
                extra_headers={"Content-Disposition": 'attachment; filename="ghostwatch-report.md"'},
            )
        elif path == "/api/report.sarif":
            with STATE_LOCK:
                audit = LAST_AUDIT
            if audit is None:
                audit = run_audit(force_demo=qs.get("demo", ["0"])[0] == "1")
                with STATE_LOCK:
                    LAST_AUDIT = audit
            sarif = json.dumps(render_sarif_report(audit), indent=2).encode("utf-8")
            self._send_bytes(
                sarif,
                "application/sarif+json; charset=utf-8",
                extra_headers={"Content-Disposition": 'attachment; filename="ghostwatch.sarif"'},
            )
        elif path == "/api/status":
            with STATE_LOCK:
                has_last = LAST_AUDIT is not None
                scans = len(AUDIT_HISTORY)
            self._send_json({
                "service": "GhostWatch",
                "version": "2.1",
                "ready": True,
                "has_last_audit": has_last,
                "scans_recorded": scans,
                "gateway_base": GATEWAY_BASE,
                "auth_enabled": bool(DASHBOARD_TOKEN),
            })
        else:
            self._send_json({"error": "Not found"}, status=404)

    def do_POST(self):
        if not self._check_auth():
            return
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path in ("/api/remediate/issue", "/api/triage"):
            payload = self._read_json_post()
            if payload is None:
                return
            if parsed.path == "/api/remediate/issue":
                try:
                    result = create_remediation_issue(payload)
                    self._send_json(result, status=200 if result.get("deduplicated") else 201)
                except GatewayHTTPError as exc:
                    self._send_json(
                        {"error": exc.message, "gateway_status": exc.status, "trace": exc.trace},
                        status=exc.status if 400 <= exc.status < 600 else 502,
                    )
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=400)
                except Exception as exc:
                    self._send_json({"error": f"Failed to create issue: {exc}"}, status=500)
            else:
                try:
                    self._send_json(triage_finding(payload), status=200)
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=400)
                except Exception as exc:
                    self._send_json({"error": f"Triage failed: {exc}"}, status=500)
        else:
            self._send_json({"error": "Not found"}, status=404)

    def log_message(self, fmt: str, *args):
        print(f"[ghostwatch] {self.address_string()} - {fmt % args}")


def main():
    load_persisted_state()
    parser = argparse.ArgumentParser(description="GhostWatch Zero-Credential Sprite Agent")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    args = parser.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"GhostWatch v2.1 listening on http://{args.host}:{args.port} (gateway: {GATEWAY_BASE})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
