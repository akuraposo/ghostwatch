# GhostWatch v2.1

A zero-credential personal GitHub security watchdog built for **Fly.io Hacksgiving 2026**.

## Why Sprites + Connectors?

Most personal coding agents require pasting a long-lived `GITHUB_TOKEN` or LLM API key into `.env` inside the sandbox. **GhostWatch** never stores a single token on disk or in environment variables. Every GitHub read, issue remediation write, and OpenRouter AI triage call routes through the **Fly.io Sprites Connector Gateway**:

```text
GET  https://api.sprites.dev/v1/gateway/github/user/repos
POST https://api.sprites.dev/v1/gateway/github/repos/<owner>/<repo>/issues
POST https://api.sprites.dev/v1/gateway/openrouter/v1/chat/completions
Authorization: (none — injected by Sprites Gateway)
```

## Key Capabilities

- **Multi-Surface Auditing:** Scans commit messages, recent commit diffs/patches (value-scoped provider prefixes + Shannon entropy filtering to avoid false positives on `os.environ[...]`), sensitive filenames, open PRs, and repository `secret_scanning` posture.
- **Runtime Zero-Credential Self-Attestation (`/api/env-proof`):** Inspects `os.environ` names and values (in-memory, never exposing raw values) plus common credential paths (`~/.git-credentials`, `~/.netrc`, `~/.ssh/id_*`, `~/.aws/credentials`, `.env`).
- **Tokenless Write Remediation (`POST /api/remediate/issue`):** Opens deduplicated GitHub Security Alert issues via the Sprites Gateway, restricted to audited repositories and guarded by JSON `Content-Type` + same-origin checks.
- **AI Triage & Fix Advisor (`POST /api/triage`):** Chains **OpenRouter Sprites Connector** → local **Ollama** (`OLLAMA_URL`) → deterministic security playbook.
- **Persistent Sprite State & Exports:** Persists audit history and remediations atomically to `ghostwatch_state.json`, and exports both **Markdown (`/api/report.md`)** and **SARIF 2.1.0 (`/api/report.sarif`)**.

## Run on a Fly.io Sprite

1. Create a Sprite on [fly.io/sprites](https://fly.io/sprites) and attach the **GitHub Connector** (and optionally the **OpenRouter Connector**).
2. Clone this repository into your Sprite and start the server:
   ```bash
   # Recommended when exposing port 8080 publicly:
   export GHOSTWATCH_DASHBOARD_TOKEN="$(openssl rand -hex 24)"
   chmod +x start.sh
   ./start.sh
   ```
3. Optional environment variables:
   - `SPRITES_GATEWAY_BASE` — override GitHub connector gateway URL
   - `SPRITES_OPENROUTER_GATEWAY` — override OpenRouter connector gateway URL
   - `OLLAMA_URL` / `GHOSTWATCH_OLLAMA_MODEL` — local Ollama fallback endpoint/model
   - `GHOSTWATCH_STATE_FILE` — custom path for persistent JSON state

## Run Locally & Tests

```bash
python -m unittest discover -p "test_*.py" -v
python ghostwatch.py --port 8080
```
