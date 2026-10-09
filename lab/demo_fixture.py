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
    blast_radius="Single non-critical app server (App Worker Node); SSH reachable only on the internal subnet.",
    verification_status=("Queried SIEM: 18 failed, 0 successful auths from this source in the last hour, all "
                         "against Application Host, its normal destination. Volume within the host's own baseline."),
    evidence=[
        "18 failed SSH login attempts from App Worker Node (172.18.0.5) to Application Host, 0 successful, in the last hour",
        "These two hosts talk constantly: thousands of sessions over the past 237 days, this is their normal path",
        "The attempt rate sits within normal range, 0.4 standard deviations above this host's own baseline",
        "Pattern is consistent with a misconfigured service retrying its credentials, not an attack",
    ],
    summary=("Routine failed SSH logins from a known internal server against the host it always talks to. "
             "No successful access and the volume is within baseline."),
    recommended_actions=["None required. Case closed automatically."],
    confidence=0.93,
)
trace1 = [
    {"kind": "alert", "label": "Alert received",
     "detail": f"Wazuh: SSH authentication failures on target-host from source {BENIGN}"},
    {"kind": "memory", "label": "Memory recall",
     "detail": "app-worker-02: known=True, normally reaches [target-host], prior verdicts {}"},
    {"kind": "siem", "label": "SIEM query (read-only)",
     "detail": f"{BENIGN} / 60m -> 18 failed, 0 successful; targets ['target-host']  |  Baseline: within normal range (0.4 sigma)"},
    {"kind": "verdict", "label": "Verdict reached", "detail": "AUTO_CLOSE, score 2/10"},
]
store_verdict(BENIGN, "target-host", v1, trace1)

# --- Scenario 2: unprecedented pivot to a crown-jewel asset -> ESCALATE (drift) ----
v2 = VerifiedVerdict(
    disposition=Disposition.escalate,
    threat_score=8,
    category=ThreatCategory.credential_access,
    mitre_techniques=["T1110.001 Password Guessing", "T1021.004 Remote Services: SSH", "T1078 Valid Accounts"],
    compromise_confirmed=False,
    blast_radius="Critical asset: Core Production Database (holds regulated data). A successful login here would be a reportable breach.",
    verification_status=("Queried SIEM: 37 failed, 0 successful auths from Production Web Server to Core Production "
                         "Database in a 5-minute window. Topology check: this source has NEVER reached the database "
                         "before, an unprecedented edge to a critical asset."),
    evidence=[
        "37 failed SSH login attempts from Production Web Server (172.18.0.7) to Core Production Database (10.0.4.12) in a 5-minute window, 0 successful",
        "These two hosts have communicated only 3 times in the last 237 days, all brief approved maintenance sessions",
        "Their normal peak is under 2 connections in any 5-minute period, so 37 is far outside the baseline (11.2 standard deviations above normal)",
        "A public-facing web server has no routine reason to open administrative SSH sessions to the database tier",
        "No successful login yet, so no confirmed break-in, but the behavior matches credential-based lateral movement",
        "Aligns with MITRE ATT&CK T1110 (brute force) pivoting into T1021.004 (remote SSH), escalated to critical for human review",
    ],
    summary=("A web server that normally only touches the application host is now brute-forcing the production "
             "database it has never contacted before. Unprecedented lateral movement toward a crown-jewel asset. "
             "No successful login yet, but this needs a human now."),
    recommended_actions=[
        "Review the Core Production Database auth and session logs for any successful login from Production Web Server",
        "Confirm whether Production Web Server to Core Production Database is ever an approved network path",
        "Check Production Web Server for signs it was itself compromised earlier, the likely origin of this pivot",
    ],
    confidence=0.9,
)
# If the optional ML layer is installed, fold its REAL output into the evidence so the
# demo reflects the behavioral model actually scoring this activity (not a canned line).
try:
    from ml.runtime import score_activity
    _HUMAN = {"new_target_ratio": "a never-before-seen destination",
              "distinct_targets": "fan-out to many hosts", "failed_auths": "the failed-login volume",
              "successful_auths": "zero successful logins", "events_per_min": "an elevated request rate",
              "off_hours": "off-hours timing", "failed_ratio": "an all-failure login pattern",
              "distinct_rules": "a spread of alert types"}
    _ba = score_activity({"failed_auth_count": 37, "successful_auth_count": 0,
                          "targets_contacted": ["secure-db"], "top_rules": [1, 2],
                          "total_alerts": 39, "window_minutes": 60,
                          "new_target_ratio": 1.0, "off_hours": 0})
    if _ba:
        _label = "ensemble of Isolation Forest + autoencoder" if "autoencoder" in _ba["models"] else "Isolation Forest"
        _drv = ", ".join(_HUMAN.get(d["feature"], d["feature"]) for d in _ba["top_drivers"][:2])
        v2.evidence.insert(2, f"Behavioral anomaly model agrees: {_ba['percentile']:.0%}-percentile anomalous "
                              f"vs the environment's learned normal ({_label}), driven by {_drv}")
except Exception:
    pass
trace2 = [
    {"kind": "alert", "label": "Alert received",
     "detail": f"Wazuh (agent 'secure-db'): repeated SSH authentication failures on secure-db from source {PIVOT}"},
    {"kind": "memory", "label": "Memory recall",
     "detail": "prod-web-01: known=True, normally reaches [target-host], prior verdicts {'auto_close': 1}"},
    {"kind": "siem", "label": "SIEM query (read-only)",
     "detail": f"{PIVOT} / 5m -> 37 failed, 0 successful; targets ['secure-db']  |  Baseline: anomalous (11.2 sigma)"},
    {"kind": "drift", "label": "Topology drift check",
     "detail": "prod-web-01 -> secure-db: UNPRECEDENTED, never-before-seen edge to a critical asset"},
    {"kind": "verdict", "label": "Verdict reached", "detail": "ESCALATE, score 8/10"},
]
store_verdict(PIVOT, "secure-db", v2, trace2)

print(f"Wrote 2 demo verdicts to {VERDICTS_FILE}")
