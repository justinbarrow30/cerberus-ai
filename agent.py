"""CerberusAI autonomous triage agent — investigates, remembers, and decides.

The agent is given read-only tools and told to investigate BEFORE concluding:
  * recall_memory   — what have we already SEEN and CONCLUDED about this entity?
  * query_siem      — live read-only SIEM investigation.
It returns a grounded VerifiedVerdict ending in a DECISION (auto_close/monitor/escalate).

The memory layer (see memory.py) is self-growing: the tool records grounded
observations and its verdicts after every run, so it gets faster and more confident
about a given environment over time — starting from an empty store on a fresh install.

Run:
    python agent.py "SSH brute-force on target-host" 172.18.0.5
Run it twice on the same IP to see the memory kick in.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx  # noqa: F401  (used indirectly by the poller's error handling)

import llm
from config import load_config
from engine import _log
from memory import Memory
from models import VerifiedVerdict
from siem import get_adapter

VERDICTS_FILE = Path(os.environ.get(
    "CERBERUS_VERDICTS", Path(__file__).resolve().parent / "outputs" / "verdicts.jsonl"))

_cfg = load_config()
_siem = get_adapter(_cfg)   # SIEM-agnostic: whatever provider config.json points at
_memory = Memory()          # auto-creates cerberus_memory.db on first use

SYSTEM_PROMPT = (
    "You are CerberusAI, an autonomous Tier-3 security triage agent with READ-ONLY "
    "investigative tools and a persistent memory of this environment. Your job is to "
    "CHECK things yourself and deliver a grounded verdict + decision — not to hand a "
    "human a to-do list.\n\n"
    "Method: (0) ALWAYS call recall_memory on the source FIRST. If we have seen it "
    "before, prior verdicts are decisive context: a long benign history supports a fast "
    "confident close; any prior escalation or confirmed compromise raises priority. "
    "(1) Use query_siem to establish scope — failed vs. SUCCESSFUL authentications from "
    "the source, over what window, against which accounts. A successful login ('Accepted') "
    "is the line between a harmless scan and a real breach, so always determine it. "
    "query_siem also returns a `statistical_baseline` — a deterministic anomaly score "
    "computed in code comparing the current failure volume to this asset's own history "
    "(e.g. '12σ above normal'). Treat it as hard, non-negotiable evidence, not opinion. "
    "query_siem also returns which targets the source contacted. (2) For a contacted "
    "target outside the source's normal pattern, call check_topology_drift(source, target): "
    "an UNPRECEDENTED edge — a source reaching a host it has never reached before — is the "
    "signature of lateral movement and should sharply raise severity toward escalate, even "
    "without a confirmed successful login. (3) Use recall_memory's business_context to "
    "reason about blast radius. (4) Conclude.\n\n"
    "Hard rules: strictly read-only — never propose changing system state. Every claim "
    "must be supported by evidence you actually retrieved (from tools or memory); if the "
    "evidence is insufficient, escalate rather than invent. Choose auto_close ONLY when "
    "evidence positively shows no compromise occurred."
)

_TOOL_DEFS = [
    {
        "name": "recall_memory",
        "description": (
            "Look up everything the tool already knows about an IP or host: business "
            "context, how many times we've investigated it, prior verdicts and their "
            "dispositions, whether compromise was ever confirmed, and recent observations. "
            "Call this FIRST — a known pattern lets you decide faster and more confidently."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"entity": {"type": "string"}},
            "required": ["entity"],
            "additionalProperties": False,
        },
    },
    {
        "name": "query_siem",
        "description": (
            "Query the Wazuh SIEM (read-only) for authentication activity from a source IP "
            "over a time window. Returns failed vs. successful auth counts, top matched "
            "rules, and sample raw log lines."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
                "window_minutes": {"type": "integer", "description": "Lookback, default 60."},
            },
            "required": ["source_ip"],
            "additionalProperties": False,
        },
    },
    {
        "name": "check_topology_drift",
        "description": (
            "Ask the network memory whether a source has EVER contacted a target before. "
            "Returns 'known_baseline' (established, normal) or 'UNPRECEDENTED' (first-ever "
            "connection — the signature of lateral movement). Use this when a source appears "
            "to reach a host outside its normal pattern."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "target": {"type": "string"},
            },
            "required": ["source", "target"],
            "additionalProperties": False,
        },
    },
]

# OpenAI/LiteLLM function-tool format — portable across every provider.
TOOLS = [
    {"type": "function", "function": {
        "name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
    for t in _TOOL_DEFS
]


# --- Tool implementations (all read-only w.r.t. the customer's systems) ------


async def query_siem(source_ip: str, window_minutes: int = 60) -> dict:
    # SIEM-agnostic: the configured adapter returns the normalized shape below,
    # whether that's Wazuh, Elastic, Security Onion, or a future Splunk/Sentinel adapter.
    result = await _siem.query_source_activity(source_ip, window_minutes)
    # Statistical baseline: a hard, deterministic anomaly score vs this asset's own
    # history (computed BEFORE we record the new sample, so it reflects the past).
    metric = f"failed_auth_{window_minutes}m"
    result["statistical_baseline"] = _memory.anomaly(source_ip, metric, result["failed_auth_count"])
    # Self-growing memory: record the grounded observation automatically.
    _memory.record_observation(source_ip, "siem_query", {
        "window_minutes": window_minutes,
        "failed_auth_count": result["failed_auth_count"],
        "successful_auth_count": result["successful_auth_count"],
        "total_alerts": result["total_alerts"],
    })
    _memory.record_metric(source_ip, metric, result["failed_auth_count"])
    # NOTE: we deliberately do NOT record the topology edges here. If we did, the
    # drift check during this same investigation would see the brand-new edge as
    # already-known and miss the lateral movement. Edges are committed to memory only
    # AFTER the verdict (see investigate), so drift reflects prior knowledge.
    return result


async def _run_tool(name: str, args: dict) -> dict:
    _log(f"tool: {name}({args})")
    if name == "recall_memory":
        return _memory.recall(args["entity"])
    if name == "query_siem":
        return await query_siem(**args)
    if name == "check_topology_drift":
        return _memory.check_topology_drift(args["source"], args["target"])
    return {"error": f"unknown tool {name}"}


# --- The agent loop ----------------------------------------------------------


def _trace_step(name: str, inp: dict, out: dict) -> dict:
    """Turn a tool call into a human-readable timeline step for the UI."""
    if name == "recall_memory":
        rels = ", ".join(r["normally_reaches"] for r in out.get("known_relationships", [])) or "none"
        return {"kind": "memory", "label": "Memory recall",
                "detail": f"{inp.get('entity')}: known={out.get('known')}, normally reaches [{rels}], "
                          f"prior verdicts {out.get('prior_disposition_tally') or '{}'}"}
    if name == "query_siem":
        base = (out.get("statistical_baseline") or {}).get("note", "")
        return {"kind": "siem", "label": "SIEM query (read-only)",
                "detail": f"{inp.get('source_ip')} / {out.get('window_minutes')}m → "
                          f"{out.get('failed_auth_count')} failed, {out.get('successful_auth_count')} successful; "
                          f"targets {out.get('targets_contacted')}"
                          + (f"  |  Baseline: {base}" if base else "")}
    if name == "check_topology_drift":
        return {"kind": "drift", "label": "Topology drift check",
                "detail": f"{inp.get('source')} → {inp.get('target')}: {out.get('status')}"}
    return {"kind": "tool", "label": name, "detail": json.dumps(inp)}


async def investigate(alert: str, primary_entity: str | None = None) -> tuple[VerifiedVerdict, list[dict]]:
    # OpenAI-style message list (system + user), portable across every provider via LiteLLM.
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Triage this SIEM alert:\n\n{alert}"},
    ]
    observed_edges: set[tuple[str, str]] = set()  # committed to memory only after the verdict
    trace: list[dict] = [{"kind": "alert", "label": "Alert received", "detail": alert}]

    for _ in range(6):  # cap on tool rounds
        resp = await llm.acompletion(messages=messages, tools=TOOLS, tool_choice="auto", max_tokens=4096)
        msg = resp.choices[0].message
        tool_calls = getattr(msg, "tool_calls", None) or []
        if not tool_calls:
            break
        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in tool_calls
            ],
        })
        for tc in tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            out = await _run_tool(tc.function.name, args)
            trace.append(_trace_step(tc.function.name, args, out))
            if tc.function.name == "query_siem":
                for t in out.get("targets_contacted", []):
                    observed_edges.add((out["source_ip"], t))
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": json.dumps(out, default=str)})

    messages.append({"role": "user", "content": "Investigation complete. Produce your final verified verdict."})
    verdict = await llm.complete_structured(messages, VerifiedVerdict, max_tokens=6000)
    trace.append({"kind": "verdict", "label": "Verdict reached",
                  "detail": f"{verdict.disposition.value.upper()} — score {verdict.threat_score}/10"})

    # Self-growing memory: record the verdict so future triage of this entity is smarter.
    if primary_entity:
        _memory.record_verdict(primary_entity, verdict.model_dump(mode="json"))
    # Commit the topology edges we observed — AFTER the verdict, so this run's drift
    # check saw prior state. Next time, these are baseline.
    for source, target in observed_edges:
        _memory.record_relationship(source, target, port=22, service="ssh")
    return verdict, trace


def store_verdict(source: str, target: str, verdict: VerifiedVerdict, trace: list[dict]) -> dict:
    """Append a dashboard-ready record to outputs/verdicts.jsonl."""
    from datetime import datetime, timezone
    unprecedented = any(s.get("kind") == "drift" and "UNPRECEDENTED" in s.get("detail", "") for s in trace)
    # Stable identity: show the asset's stable id (hostname/asset), keep the live IP
    # as a pointer. This is what survives DHCP churn / container restarts / autoscaling.
    source_id = _memory.resolve_identity(source)
    source_ip = _memory.current_ip(source_id) or (source if _memory._is_ip(source) else None)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source_id,
        "source_ip": source_ip,
        "target": target,
        "disposition": verdict.disposition.value,
        "threat_score": verdict.threat_score,
        "category": verdict.category.value,
        "compromise_confirmed": verdict.compromise_confirmed,
        "blast_radius": verdict.blast_radius,
        "verification_status": verdict.verification_status,
        "summary": verdict.summary,
        "mitre_techniques": verdict.mitre_techniques,
        "evidence": verdict.evidence,
        "recommended_actions": verdict.recommended_actions,
        "confidence": verdict.confidence,
        "trace": trace,
        "unprecedented_edge": unprecedented,
    }
    VERDICTS_FILE.parent.mkdir(exist_ok=True)
    with VERDICTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
    return record


async def _main() -> None:
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    alert = sys.argv[1] if len(sys.argv) > 1 else "SSH brute-force activity from 172.18.0.5"
    primary = sys.argv[2] if len(sys.argv) > 2 else None
    if primary:
        alert += f" (source IP {primary})"

    prior = _memory.recall(primary) if primary else {}
    _log(f"investigating: {alert}")
    _log(f"memory before: {_memory.stats()}")

    v, _trace = await investigate(alert, primary_entity=primary)

    print("\n" + "=" * 70)
    seen = prior.get("times_investigated", 0)
    print(f"MEMORY           : {'seen '+str(seen)+'x before → '+str(prior.get('prior_disposition_tally')) if seen else 'first time seeing this entity'}")
    print(f"DISPOSITION      : {v.disposition.value.upper()}   (score {v.threat_score}/10, confidence {v.confidence:.0%})")
    print(f"COMPROMISE       : {'CONFIRMED' if v.compromise_confirmed else 'no evidence of success'}")
    print(f"CATEGORY / MITRE : {v.category.value}  |  {', '.join(v.mitre_techniques) or '—'}")
    print(f"BLAST RADIUS     : {v.blast_radius}")
    print(f"VERIFIED         : {v.verification_status}")
    print(f"SUMMARY          : {v.summary}")
    print("EVIDENCE (from tools + memory):")
    for e in v.evidence:
        print(f"   • {e}")
    print("NEXT STEPS       :")
    for a in v.recommended_actions:
        print(f"   • {a}")
    print(f"\nmemory after     : {_memory.stats()}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(_main())
