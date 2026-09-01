"""Populate the dashboard with two REAL investigations, using two real sources:

  * 172.18.0.5  → only ever hit target-host (its baseline)      => AUTO_CLOSE
  * 172.18.0.7  → the pivoting attacker, now reaching secure-db => ESCALATE (drift)

Nothing is faked — we only reset the secure-db topology edge so the pivot reads as
'unprecedented' again, and let the agent investigate live data + memory.

    python lab/seed_dashboard.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from agent import VERDICTS_FILE, investigate, store_verdict  # noqa: E402
from memory import Memory  # noqa: E402

BENIGN = "172.18.0.5"   # historical: only ever hit target-host
PIVOT = "172.18.0.7"    # current attacker: now hitting the critical DB


async def main() -> None:
    m = Memory()
    VERDICTS_FILE.parent.mkdir(exist_ok=True)
    VERDICTS_FILE.write_text("", encoding="utf-8")

    # Stable identity: bind each source IP to a stable asset id (in production this
    # comes from the Wazuh agent name / asset inventory / EDR). Memory now keys on
    # these, so history survives the IP churn we hit earlier.
    m.bind_identity("app-worker-02", BENIGN, "server")
    m.bind_identity("prod-web-01", PIVOT, "server")
    benign_id = m.resolve_identity(BENIGN)   # -> app-worker-02
    pivot_id = m.resolve_identity(PIVOT)      # -> prod-web-01

    # Keep the benign source's baseline; ensure it has no secure-db edge.
    m.record_relationship(BENIGN, "target-host", 22, "ssh")
    m._conn.execute("DELETE FROM relationships WHERE source=? AND target=?", (benign_id, "secure-db"))
    # Pivot source: known baseline is target-host; reset secure-db so drift fires.
    m.record_relationship(PIVOT, "target-host", 22, "ssh")
    m._conn.execute("DELETE FROM relationships WHERE source=? AND target=?", (pivot_id, "secure-db"))
    m._conn.commit()

    print(f"→ investigating {BENIGN} (baseline target — expect AUTO_CLOSE)...")
    v1, t1 = await investigate(
        f"Wazuh alerts: SSH authentication failures on target-host from source {BENIGN}", primary_entity=BENIGN)
    store_verdict(BENIGN, "target-host", v1, t1)
    print(f"   {v1.disposition.value.upper()} ({v1.threat_score}/10)")

    # investigate() may have committed a fresh edge; clear the pivot's secure-db edge again.
    m._conn.execute("DELETE FROM relationships WHERE source=? AND target=?", (pivot_id, "secure-db"))
    m._conn.commit()

    print(f"→ investigating {PIVOT} (critical DB — expect ESCALATE via drift)...")
    v2, t2 = await investigate(
        f"Wazuh alert from agent 'secure-db': repeated SSH authentication failures on secure-db from source {PIVOT}",
        primary_entity=PIVOT)
    store_verdict(PIVOT, "secure-db", v2, t2)
    print(f"   {v2.disposition.value.upper()} ({v2.threat_score}/10)")
    print(f"\nWrote {VERDICTS_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
