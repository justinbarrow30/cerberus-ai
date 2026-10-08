"""See the console without standing up the lab — writes two DEMO verdicts.

These go through the SAME store_verdict() path the live agent uses, so the records
are shaped exactly like real ones. The scenario mirrors the investigation we
validated live: a server auto-closed on its normal baseline, then escalated when it
pivoted to a critical database it had never touched before (topology drift).

    python lab/demo_fixture.py       # then open the dashboard

These are illustrative fixtures for demos/screenshots, NOT a live capture. For real
verdicts, connect a SIEM + LLM in the setup wizard.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

import agent  # noqa: E402
from agent import VERDICTS_FILE, store_verdict  # noqa: E402
from models import Disposition, ThreatCategory, VerifiedVerdict  # noqa: E402

BENIGN = "172.18.0.5"   # app-worker-02 — only ever talks to target-host (its baseline)
PIVOT = "172.18.0.7"    # prod-web-01 — pivots to the critical DB it has never touched

m = agent._memory
VERDICTS_FILE.parent.mkdir(exist_ok=True)
VERDICTS_FILE.write_text("", encoding="utf-8")

# Stable identity: bind each live IP to a stable asset id (in production this comes
# from the Wazuh agent name / asset inventory / EDR), so history survives IP churn.
m.bind_identity("app-worker-02", BENIGN, "server")
m.bind_identity("prod-web-01", PIVOT, "server")
m.record_relationship(BENIGN, "target-host", 22, "ssh")
m.record_relationship(PIVOT, "target-host", 22, "ssh")

# --- Scenario 1: benign, on-baseline -> AUTO_CLOSE --------------------------------
v1 = VerifiedVerdict(
    disposition=Disposition.auto_close,
    threat_score=2,
    category=ThreatCategory.brute_force,
    mitre_techniques=["T1110.001 Password Guessing"],
    compromise_confirmed=False,
    blast_radius="Single non-critical app server (app-worker-02); SSH reachable only on the internal subnet.",
    verification_status=("Queried SIEM: 18 failed / 0 successful auths from this source in 60m, "
                         "all against target-host — its normal destination. Volume within the host's own baseline."),
    evidence=[
        "18 failed SSH auths and 0 successful in the last 60m",
        "Only target contacted: target-host (matches the 30-day baseline)",
        "Statistical baseline: within normal range for this asset (0.4σ)",
        "No prior escalations recorded for app-worker-02",
    ],
    summary=("Routine failed SSH logins from a known internal server against the host it always talks to. "
             "No successful access and the volume is within baseline."),
    recommended_actions=["none required"],
    confidence=0.93,
)
trace1 = [
    {"kind": "alert", "label": "Alert received",
     "detail": f"Wazuh: SSH authentication failures on target-host from source {BENIGN}"},
    {"kind": "memory", "label": "Memory recall",
     "detail": "app-worker-02: known=True, normally reaches [target-host], prior verdicts {}"},
    {"kind": "siem", "label": "SIEM query (read-only)",
     "detail": f"{BENIGN} / 60m → 18 failed, 0 successful; targets ['target-host']  |  Baseline: within normal range (0.4σ)"},
    {"kind": "verdict", "label": "Verdict reached", "detail": "AUTO_CLOSE — score 2/10"},
]
store_verdict(BENIGN, "target-host", v1, trace1)

# --- Scenario 2: unprecedented pivot to a crown-jewel asset -> ESCALATE (drift) ----
v2 = VerifiedVerdict(
    disposition=Disposition.escalate,
    threat_score=8,
    category=ThreatCategory.credential_access,
    mitre_techniques=["T1110.001 Password Guessing", "T1021.004 Remote Services: SSH"],
    compromise_confirmed=False,
    blast_radius="Critical asset: secure-db (production database holding regulated data). Successful access here would be a reportable breach.",
    verification_status=("Queried SIEM: 63 failed / 0 successful auths from this source in 60m against secure-db. "
                         "Topology check: this source has NEVER contacted secure-db before — an unprecedented edge to a critical asset."),
    evidence=[
        "63 failed SSH auths and 0 successful in the last 60m",
        "Target is secure-db, a critical production database",
        "Topology drift: prod-web-01 → secure-db is an unprecedented edge (never seen in 30 days)",
        "This source normally only reaches target-host — the new destination is lateral movement",
        "Statistical baseline: anomalous (11.2σ above this source's own norm)",
    ],
    summary=("A server that normally only touches target-host is now brute-forcing the production database it has "
             "never contacted before — unprecedented lateral movement toward a crown-jewel asset. No successful "
             "login yet, but this needs a human now."),
    recommended_actions=[
        "Review secure-db auth/session logs for any successful login from prod-web-01 in the last 60m",
        "Confirm whether prod-web-01 → secure-db is ever an approved network path",
        "Check prod-web-01 for signs it was itself compromised earlier (the pivot's origin)",
    ],
    confidence=0.9,
)
trace2 = [
    {"kind": "alert", "label": "Alert received",
     "detail": f"Wazuh (agent 'secure-db'): repeated SSH authentication failures on secure-db from source {PIVOT}"},
    {"kind": "memory", "label": "Memory recall",
     "detail": "prod-web-01: known=True, normally reaches [target-host], prior verdicts {'auto_close': 1}"},
    {"kind": "siem", "label": "SIEM query (read-only)",
     "detail": f"{PIVOT} / 60m → 63 failed, 0 successful; targets ['secure-db']  |  Baseline: anomalous (11.2σ)"},
    {"kind": "drift", "label": "Topology drift check",
     "detail": "prod-web-01 → secure-db: UNPRECEDENTED — never-before-seen edge to a critical asset"},
    {"kind": "verdict", "label": "Verdict reached", "detail": "ESCALATE — score 8/10"},
]
store_verdict(PIVOT, "secure-db", v2, trace2)

print(f"Wrote 2 demo verdicts to {VERDICTS_FILE}")
