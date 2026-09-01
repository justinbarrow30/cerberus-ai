"""Poll the Wazuh Indexer for new high-severity alerts and triage each one.

IMPORTANT correctness note: Wazuh *alerts* are stored in the Wazuh Indexer
(an OpenSearch instance, port 9200), NOT in the Manager API (port 55000). The
Manager API is for agents/rules/config. So this poller queries the indexer's
`wazuh-alerts-*` index — that is where the real detections land.

Flow:  indexer (wazuh-alerts-*)  ->  engine.triage()  ->  outputs/live_triage.jsonl

Run from the repo root once the Wazuh stack + attack-lab are up:
    python lab/wazuh_poller.py

Config via env (defaults match a stock single-node deployment):
    INDEXER_URL   default https://localhost:9200
    INDEXER_USER  default admin
    INDEXER_PASS  default SecretPassword
    MIN_LEVEL     default 7           (Wazuh rule.level threshold)
    POLL_SECONDS  default 5
Needs ANTHROPIC_API_KEY for the triage calls.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine import triage  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

INDEXER_URL = os.environ.get("INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.environ.get("INDEXER_USER", "admin")
INDEXER_PASS = os.environ.get("INDEXER_PASS", "SecretPassword")
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "7"))
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "5"))

OUTFILE = Path(__file__).resolve().parent.parent / "outputs" / "live_triage.jsonl"


async def fetch_new_alerts(client: httpx.AsyncClient, since_iso: str) -> list[dict]:
    """Return alerts with rule.level >= MIN_LEVEL newer than `since_iso`, oldest first."""
    query = {
        "size": 50,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"rule.level": {"gte": MIN_LEVEL}}},
                    {"range": {"@timestamp": {"gt": since_iso}}},
                ]
            }
        },
    }
    resp = await client.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        json=query,
        auth=(INDEXER_USER, INDEXER_PASS),
    )
    resp.raise_for_status()
    return resp.json().get("hits", {}).get("hits", [])


async def main() -> None:
    OUTFILE.parent.mkdir(exist_ok=True)
    seen_ids: set[str] = set()
    # Only triage alerts that arrive after we start.
    since = datetime.now(timezone.utc).isoformat()

    print(f"Polling {INDEXER_URL} for rule.level>={MIN_LEVEL} every {POLL_SECONDS}s. "
          f"Ctrl-C to stop.\n", file=sys.stderr)

    # verify=False: the single-node stack uses self-signed certs. Fine for a lab.
    # (Files aren't async context managers, so the sink gets its own plain `with`.)
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
      with OUTFILE.open("a", encoding="utf-8") as sink:
        while True:
            try:
                hits = await fetch_new_alerts(client, since)
            except httpx.HTTPError as e:
                print(f"[poller] indexer query failed: {e} (retrying)", file=sys.stderr)
                await asyncio.sleep(POLL_SECONDS)
                continue

            for hit in hits:
                alert_id = hit.get("_id", "")
                if alert_id in seen_ids:
                    continue
                seen_ids.add(alert_id)
                src = hit.get("_source", {})
                since = max(since, src.get("@timestamp", since))

                rule = src.get("rule", {})
                full_log = src.get("full_log") or json.dumps(src.get("data", {}))
                if not full_log.strip():
                    continue

                # Enrich with Wazuh's OWN correlation context. `full_log` alone is
                # just the single underlying line — for a correlated rule (e.g. a
                # brute-force burst at level 10) that line looks like one harmless
                # failure. Passing the rule description + level lets the engine
                # reflect the real severity instead of judging one line in isolation.
                alert_text = (
                    f"SIEM alert from Wazuh (rule level {rule.get('level')}): "
                    f"{rule.get('description')}\n"
                    f"Underlying log line: {full_log}"
                )

                result = await triage(alert_text)
                record = {
                    "alert_id": alert_id,
                    "wazuh_rule": rule.get("description"),
                    "wazuh_level": rule.get("level"),
                    "agent": src.get("agent", {}).get("name"),
                    "raw_log": full_log,
                    **result.model_dump(),
                }
                record["category"] = result.category.value
                sink.write(json.dumps(record) + "\n")
                sink.flush()

                flag = "[CRIT]" if result.threat_score >= 7 else "[WARN]"
                print(f"{flag} wazuh L{rule.get('level')} \"{rule.get('description')}\" "
                      f"-> cerberus [{result.threat_score}/10] {result.category.value}: "
                      f"{result.summary}")

            await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
