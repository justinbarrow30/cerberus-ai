# CerberusAI — Read-Only Security Log Triage Engine (MCP)

> This file is Claude Code's persistent context for this repo. Keep it accurate.
> If something here turns out to be wrong, fix the file — don't paper over it in code.

## 1. What this is (and what it is not)

CerberusAI is a **read-only** security-log triage engine. It ingests one raw SIEM /
syslog event (Splunk, Elastic, Wazuh, plain syslog) and returns **structured,
validated** triage intelligence: is this an active exploit, how severe, what kind,
a one-line summary, the observables, and read-only investigative next steps.

- It **does not** modify system state, patch, quarantine, or write to any target.
- It **does not** need admin/write credentials on the monitored infrastructure.
- That read-only posture is the commercial point: it's far easier to get approved
  by a risk-averse security or government team than anything that can change state.

**This is also a learning project.** The owner is using it to actually understand
MCP servers, structured outputs, prompt caching, and modern agent patterns — so
prefer clarity and correctness over cleverness, and leave short comments explaining
*why* a pattern is used, not just what it does.

## 2. Architecture (transport is separate from logic — on purpose)

```
MCP client (Claude Desktop / Code)                Direct callers (tests, a future
        │  stdio (JSON-RPC)                         FastAPI endpoint, a Wazuh poller)
        ▼                                                        │
   server.py  ──────────────► engine.triage(raw_log) ◄──────────┘
   (FastMCP tool wrapper)      (the actual logic: Anthropic API
                               call + Pydantic-validated output)
```

- `engine.py` — the real work. One async function, `triage(raw_log) -> TriageResult`,
  that calls the Anthropic API and returns a validated Pydantic model. No MCP here,
  so it's trivially unit-testable and reusable.
- `server.py` — a thin `MCPServer` wrapper that exposes `analyze_security_log` as an
  MCP tool. Transport only.
- `models.py` — the `TriageResult` Pydantic schema. This schema *is* the contract
  and also steers the model (field descriptions become the JSON schema).

**Golden rule for MCP over stdio:** stdout is the JSON-RPC channel. **All logging
goes to stderr.** Writing status text to stdout corrupts the protocol.

## 3. Correct, current API facts (do not regress these)

- **Model:** configurable via `CERBERUS_MODEL`; default `claude-opus-5`.
  For high-volume single-line triage, `claude-haiku-4-5` or `claude-sonnet-5` are
  the economical production choices. The env var exists so we can A/B them.
- **Determinism comes from structured outputs, not temperature.** `temperature` is
  *removed* on current Opus/Sonnet/Fable models (sending it returns HTTP 400). Do
  not add it.
- **Structured output** uses `client.messages.parse(..., output_format=TriageResult)`
  → `response.parsed_output` is a validated `TriageResult`. This replaces the older
  `tool_choice`-forcing trick.
- **Extended thinking** is adaptive (`thinking={"type":"adaptive"}`) on current
  models; the old `budget_tokens` is rejected. We leave defaults for now.
- **Never hardcode dated model IDs** like `claude-3-5-sonnet-20241022`. Use the bare
  current IDs.

## 4. Tech stack

- Python 3.11+ in a `.venv`
- `mcp` (2.x high-level server: `from mcp.server import MCPServer` — the class was
  called `FastMCP` in 1.x; the standalone `fastmcp` package still uses that name)
- `anthropic` (async client)
- `pydantic` (schema + validation)

## 5. Roadmap

### Phase 1 — Triage engine + MCP server  ✅ (this scaffold)
- [x] `TriageResult` Pydantic schema
- [x] `engine.triage()` using `messages.parse`, logging to stderr
- [x] `server.py` FastMCP tool `analyze_security_log`
- [x] `test_engine.py` direct-call harness + sample logs

### Phase 2 — Live-fire lab (free / open source)  ✅ built (see `lab/`)
Real Wazuh is a **3-container** stack (indexer + manager + dashboard), not the
single container in the original sketch, and you cannot fake ingestion by echoing
into a shared volume. What's in `lab/`:
- [x] `lite_pipeline.py` — no-Docker demo: simulated stream → `triage()` → JSONL
- [x] `attack-lab.yml` — compose overlay: target (sshd + real Wazuh agent) + attacker
- [x] `target/` — Dockerfile + entrypoint that enrolls a genuine Wazuh agent
- [x] `attacker/attack.sh` — scripted SSH brute force → real alerts
- [x] `wazuh_poller.py` — reads new alerts from the **Wazuh Indexer** (not the
      Manager API — a key correction) and pipes each through `engine.triage()`
- Layers on the official `wazuh/wazuh-docker` single-node stack rather than
  reinventing its cert/deploy setup. Not yet runtime-verified end-to-end.

### Phase 3 — Optimization & packaging  ⬜
- [ ] Prompt caching for the system prompt (only helps once the cached prefix is
      ≥ ~1024 tokens — don't add it before it actually caches, or it's a silent no-op)
- [ ] `effort`/thinking tuning for latency vs. quality
- [ ] Optional FastAPI HTTP wrapper around `engine.triage()`
- [ ] `claude_desktop_config.json` to register the server in Claude Desktop

## 6. Conventions

- Type-hint everything. Async for anything doing I/O.
- Keep `engine.py` free of MCP imports; keep `server.py` free of business logic.
- Secrets via environment (`ANTHROPIC_API_KEY`); never commit `.env`.
