"""Live poller that drives the AUTONOMOUS AGENT (not just the flat engine).

Polls the Wazuh indexer for new high-severity alerts, groups them by source, and
for each newly-seen source runs the full investigate() loop — SIEM queries, memory
recall, topology-drift checks — then writes a dashboard-ready verdict (AUTO_CLOSE /
ESCALATE) to outputs/verdicts.jsonl, which dashboard.py renders live.

Run:  python agent_poller.py         (needs the lab running + ANTHROPIC_API_KEY)

Cost note: each source triggers a full agent investigation (several LLM calls), so
we investigate a given source at most once per DEDUPE_MINUTES, not per raw alert.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time

import httpx

from agent import _memory, _siem, investigate, store_verdict

_CRIT = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def pick_target(targets: list[str]) -> str:
    """Frame the incident on the most critical asset the source touched — a pivot
    onto a critical DB matters more than noise against a low-value host."""
    if not targets:
        return "unknown"
    return max(targets, key=lambda t: _CRIT.get(_memory._seed.get(t, {}).get("criticality"), 0))


POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "10"))
DEDUPE_MINUTES = float(os.environ.get("DEDUPE_MINUTES", "10"))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


async def main() -> None:
    last_investigated: dict[str, float] = {}
    print(f"Agent poller live (SIEM: {_siem.__class__.__name__}), every {POLL_SECONDS}s. Ctrl-C to stop.\n",
          file=sys.stderr)
    while True:
        try:
            incidents = await _siem.list_recent_sources(window_min=10)
        except httpx.HTTPError as e:
            print(f"[poller] SIEM query failed: {e}", file=sys.stderr)
            await asyncio.sleep(POLL_SECONDS)
            continue

        for inc in incidents:
            src = inc["source"]
            if time.time() - last_investigated.get(src, 0) < DEDUPE_MINUTES * 60:
                continue
            last_investigated[src] = time.time()
            targets = inc["targets"] or ["unknown"]
            primary_target = pick_target(targets)
            alert = (f"SIEM alerts ({inc['alert_count']} in 10m): authentication failures "
                     f"on {', '.join(targets)} from source {src}")
            print(f"[poller] investigating {src} -> {targets} ...", file=sys.stderr)
            verdict, trace = await investigate(alert, primary_entity=src)
            store_verdict(src, primary_target, verdict, trace)
            print(f"[poller] {src}: {verdict.disposition.value.upper()} ({verdict.threat_score}/10)",
                  file=sys.stderr)

        await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
