"""Structured output contract for CerberusAI.

This Pydantic model is the single source of truth for what a triage looks like.
Field descriptions are not just docs: `client.messages.parse(output_format=...)`
turns them into the JSON schema the model is constrained to, so they double as
lightweight instructions. Keep them crisp and behavioral.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    """Coarse MITRE-flavored bucket. `unknown` is allowed so the model never guesses."""

    brute_force = "brute_force"
    credential_access = "credential_access"
    injection = "injection"  # SQLi, command injection, etc.
    malware = "malware"
    reconnaissance = "reconnaissance"
    privilege_escalation = "privilege_escalation"
    data_exfiltration = "data_exfiltration"
    policy_violation = "policy_violation"
    benign = "benign"
    unknown = "unknown"


class TriageResult(BaseModel):
    """Structured triage of a single raw log event."""

    is_active_exploit: bool = Field(
        description=(
            "True only when the log shows an in-progress or successful attack, "
            "not a mere anomaly, misconfiguration, or single failed login."
        )
    )
    threat_score: int = Field(
        ge=0,
        le=10,
        description="0 = clearly benign, 10 = confirmed critical compromise in progress.",
    )
    category: ThreatCategory = Field(
        description="Best-fit attack category; use 'unknown' rather than guessing."
    )
    summary: str = Field(
        description=(
            "One or two plain sentences a tier-1 SOC analyst can read at a glance. "
            "No preamble, no markdown."
        )
    )
    indicators: list[str] = Field(
        default_factory=list,
        description=(
            "Observables pulled verbatim from the log: source IPs, usernames, "
            "hostnames, URLs, file hashes, ports. Empty list if none."
        ),
    )
    recommended_triage_actions: list[str] = Field(
        description=(
            "Concrete, strictly READ-ONLY investigative next steps (e.g. 'check "
            "whether 192.168.1.50 has prior failed logins across other hosts'). "
            "Never suggest changing system state, blocking, patching, or quarantining."
        )
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Model's confidence in this assessment, 0.0 to 1.0.",
    )


class Disposition(str, Enum):
    """The DECISION — the point of the whole tool. What should happen to this alert."""

    auto_close = "auto_close"      # benign / confirmed contained; analyst never needs to see it
    monitor = "monitor"           # not urgent, but keep an eye on the source
    escalate = "escalate"         # a human needs to act now


class VerifiedVerdict(BaseModel):
    """An autonomous, evidence-backed verdict — produced only AFTER the agent has
    used its tools to investigate. Every claim must trace to retrieved evidence;
    the agent abstains (low confidence, escalate) rather than inventing a story."""

    disposition: Disposition = Field(
        description="The decision. Pick auto_close ONLY when evidence positively shows the "
        "alert is benign or a confirmed-contained failure with no successful compromise."
    )
    threat_score: int = Field(ge=0, le=10)
    category: ThreatCategory
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK IDs + names actually supported by the evidence, "
        "e.g. 'T1110.001 Password Guessing'. Empty if none apply.",
    )
    compromise_confirmed: bool = Field(
        description="True ONLY if retrieved evidence shows a successful login / access "
        "(e.g. an 'Accepted password' event), not merely attempts."
    )
    blast_radius: str = Field(
        description="What is actually at risk given the asset context, e.g. "
        "'single isolated lab container' vs 'domain controller on corporate LAN'."
    )
    verification_status: str = Field(
        description="Plain-English record of what the agent CHECKED and what it FOUND "
        "(the automated investigation), e.g. 'Queried SIEM: 47 failed / 0 successful auths "
        "from this IP in 60m across 6 usernames.'"
    )
    evidence: list[str] = Field(
        description="Concrete facts pulled from the tools that justify the verdict. "
        "If this list is empty, the verdict is not trustworthy — do not auto_close."
    )
    summary: str = Field(description="One or two sentences for a tier-1 analyst.")
    recommended_actions: list[str] = Field(
        description="Read-only next steps only, or 'none required' if auto_close."
    )
    confidence: float = Field(ge=0.0, le=1.0)
