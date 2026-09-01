"""CerberusAI triage engine — the actual logic, independent of any transport.

Deliberately free of MCP imports so it can be:
  * unit-tested directly (see test_engine.py),
  * reused behind a FastAPI endpoint or a Wazuh poller later.

Determinism note: current Anthropic models (Opus/Sonnet/Fable 5-series) reject the
`temperature` parameter. We get reliable, machine-readable output from *structured
outputs* (`messages.parse` + a Pydantic schema), not from temperature=0.
"""

from __future__ import annotations

import sys
from pathlib import Path

import llm
from models import TriageResult

# Auto-load .env (git-ignored) for local dev; the shipped tool is configured via
# the GUI wizard (config.json) instead. No-op if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass

# Kept for compatibility (e.g. server.py log lines). The real provider/model is
# resolved per-call inside llm.py from config.json (whatever LLM the user chose).
MODEL: str = llm.model_label()

SYSTEM_PROMPT = (
    "You are CerberusAI, a read-only security-operations triage engine. "
    "You receive a single raw log event from a SIEM or syslog feed and assess it. "
    "You are strictly passive: you observe and advise, you never change system state. "
    "Every recommended action you produce must be read-only investigation "
    "(look, correlate, check history) — never block, patch, quarantine, or reset. "
    "If an event is benign or merely noisy, say so honestly with a low threat_score; "
    "do not inflate severity. Base every field only on what the log actually shows."
)


def _log(message: str) -> None:
    """Status logging for humans. MUST go to stderr: on the MCP stdio transport,
    stdout is the JSON-RPC channel and any stray text there corrupts the protocol."""
    print(f"[cerberus] {message}", file=sys.stderr, flush=True)


# --- Core logic --------------------------------------------------------------


async def triage(raw_log: str) -> TriageResult:
    """Triage one raw log event and return a validated TriageResult, using whatever
    LLM provider the user configured (BYO-LLM)."""
    preview = raw_log.strip().replace("\n", " ")[:80]
    _log(f"triage ({len(raw_log)} chars) via {MODEL}: {preview!r}")

    result = await llm.complete_structured(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Triage this single log event:\n\n{raw_log}"},
        ],
        TriageResult,
        max_tokens=2048,
    )
    _log(
        f"-> score={result.threat_score} category={result.category.value} "
        f"exploit={result.is_active_exploit} confidence={result.confidence:.2f}"
    )
    return result
