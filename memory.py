"""CerberusAI environment memory — the layer that makes the tool learn a network.

Product-baked and self-growing: a single SQLite file, created automatically on
first use, that starts EMPTY and fills itself as the agent works. Ship it with a
new customer and it begins learning their environment on the very first alert —
no hand-authored asset inventory required.

Design choices that matter:
  * SQLite (stdlib, zero deps) so the store is portable and part of the tool.
  * CODE writes memory, never the LLM — only grounded facts (observed SIEM counts,
    reached verdicts) are persisted, so a hallucination can't poison future triage.
  * Entity-keyed (IP / host). Recall returns what we've SEEN and CONCLUDED before,
    which is the compounding signal: a source with a long benign history closes
    instantly; one with a prior escalation is flagged on sight.

An optional seed file (lab/assets.json) can pre-load business facts a tool can't
infer on its own (e.g. 'this host is a domain controller'), but it is NOT required.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import statistics
import time
from collections import Counter
from pathlib import Path

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_DEFAULT_DB = Path(__file__).resolve().parent / "cerberus_memory.db"
_DEFAULT_SEED = Path(__file__).resolve().parent / "lab" / "assets.json"

# TODO (enterprise hardening — Stable Identity Mapping):
#   Memory is currently keyed on raw IP. In container/cloud environments IPs are
#   ephemeral (we watched the attacker jump 172.18.0.5 -> .0.7 on a container
#   restart), so IP-keyed memory "forgets" a workload every time it reschedules.
#   Fix: add an `identities` table mapping a STABLE key (hostname / container_id /
#   workload label) -> current IP, and key relationships/verdicts on the stable id.
#   query_siem should resolve the IP to its stable identity before recording.


class Memory:
    def __init__(self, db_path: str | Path | None = None, seed_path: str | Path | None = None):
        self.db_path = Path(os.environ.get("CERBERUS_MEMORY_DB", db_path or _DEFAULT_DB))
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        # Optional, non-required seed of business facts the tool can't infer.
        self._seed = self._load_seed(seed_path or _DEFAULT_SEED)

    # --- setup ---------------------------------------------------------------

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS entities (
                entity TEXT PRIMARY KEY,
                first_seen REAL,
                last_seen REAL,
                times_investigated INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity TEXT, ts REAL, source TEXT, facts TEXT
            );
            CREATE TABLE IF NOT EXISTS verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity TEXT, ts REAL, disposition TEXT, category TEXT,
                threat_score INTEGER, compromise_confirmed INTEGER, summary TEXT
            );
            -- The topology ledger: who talks to whom, over what service.
            -- NOTE: `port` is the SERVICE port (e.g. 22 for ssh), inferred from the
            -- log source — NOT the client's ephemeral port. A full arbitrary-service
            -- map (e.g. 3306) needs network-FLOW data (Zeek/firewall), which auth
            -- logs don't provide; this table learns what our data actually supports.
            CREATE TABLE IF NOT EXISTS relationships (
                source TEXT, target TEXT, port INTEGER, service TEXT,
                first_seen REAL, last_seen REAL, connection_count INTEGER DEFAULT 0,
                PRIMARY KEY (source, target, port)
            );
            -- Stable Identity Mapping Layer. Enterprise assets (laptops via DHCP,
            -- auto-scaling cloud VMs, containers) change IP constantly, so memory is
            -- keyed on a STABLE id (hostname / agent name / asset id), with the IP kept
            -- only as a live pointer. This is what lets the brain survive restarts.
            CREATE TABLE IF NOT EXISTS identities (
                stable_id TEXT PRIMARY KEY, kind TEXT,
                current_ip TEXT, ip_history TEXT,
                first_seen REAL, last_seen REAL
            );
            -- Statistical baselines: a time series of numeric metrics per asset
            -- (e.g. failed-auth volume). We compute mean + standard deviation from
            -- this so the CODE can hand the LLM a hard anomaly score ("12σ above
            -- normal") instead of the model guessing whether a number is high.
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity TEXT, ts REAL, name TEXT, value REAL
            );
            """
        )
        self._conn.commit()

    @staticmethod
    def _load_seed(seed_path: str | Path) -> dict:
        try:
            return json.loads(Path(seed_path).read_text(encoding="utf-8")).get("assets", {})
        except (OSError, json.JSONDecodeError):
            return {}

    # --- stable identity -----------------------------------------------------

    @staticmethod
    def _is_ip(v: str) -> bool:
        return bool(_IPV4.match(v or ""))

    def _upsert_identity(self, stable_id: str, kind: str, ip: str | None) -> None:
        now = time.time()
        row = self._conn.execute("SELECT ip_history FROM identities WHERE stable_id=?", (stable_id,)).fetchone()
        hist = json.loads(row["ip_history"]) if row and row["ip_history"] else []
        if ip and ip not in hist:
            hist.append(ip)
        self._conn.execute(
            """INSERT INTO identities (stable_id, kind, current_ip, ip_history, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(stable_id) DO UPDATE SET
                 current_ip=COALESCE(excluded.current_ip, identities.current_ip),
                 ip_history=excluded.ip_history, last_seen=excluded.last_seen""",
            (stable_id, kind, ip, json.dumps(hist), now, now),
        )
        self._conn.commit()

    def bind_identity(self, stable_id: str, ip: str, kind: str = "asset") -> None:
        """Attach an IP to a stable asset id (what an asset inventory / EDR / Wazuh
        agent registration provides in production). Used so a workload keeps its
        history when its IP changes."""
        self._upsert_identity(stable_id, kind, ip)

    def resolve_identity(self, value: str) -> str:
        """Map an IP or hostname to its stable id. Hostnames are already stable.
        A known IP resolves to its bound asset; an unknown IP registers as itself."""
        if not value:
            return value
        if not self._is_ip(value):          # already a stable hostname / asset id
            self._upsert_identity(value, "host", None)
            return value
        row = self._conn.execute("SELECT stable_id FROM identities WHERE current_ip=?", (value,)).fetchone()
        if row:
            return row["stable_id"]
        for r in self._conn.execute("SELECT stable_id, ip_history FROM identities").fetchall():
            if value in json.loads(r["ip_history"] or "[]"):
                self._conn.execute("UPDATE identities SET current_ip=?, last_seen=? WHERE stable_id=?",
                                   (value, time.time(), r["stable_id"]))
                self._conn.commit()
                return r["stable_id"]
        self._upsert_identity(value, "ip", value)   # unmanaged / external — key on IP
        return value

    def current_ip(self, stable_id: str) -> str | None:
        row = self._conn.execute("SELECT current_ip FROM identities WHERE stable_id=?", (stable_id,)).fetchone()
        return row["current_ip"] if row else None

    # --- writes (code-driven, grounded only) ---------------------------------

    def _touch_entity(self, entity: str) -> None:
        now = time.time()
        self._conn.execute(
            """INSERT INTO entities (entity, first_seen, last_seen, times_investigated)
               VALUES (?, ?, ?, 0)
               ON CONFLICT(entity) DO UPDATE SET last_seen=excluded.last_seen""",
            (entity, now, now),
        )
        self._conn.commit()

    def record_observation(self, entity: str, source: str, facts: dict) -> None:
        entity = self.resolve_identity(entity)
        self._touch_entity(entity)
        self._conn.execute(
            "INSERT INTO observations (entity, ts, source, facts) VALUES (?, ?, ?, ?)",
            (entity, time.time(), source, json.dumps(facts, default=str)),
        )
        self._conn.commit()

    def record_verdict(self, entity: str, verdict: dict) -> None:
        entity = self.resolve_identity(entity)
        self._touch_entity(entity)
        self._conn.execute(
            """INSERT INTO verdicts
               (entity, ts, disposition, category, threat_score, compromise_confirmed, summary)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                entity, time.time(),
                verdict.get("disposition"), verdict.get("category"),
                verdict.get("threat_score"), int(bool(verdict.get("compromise_confirmed"))),
                verdict.get("summary"),
            ),
        )
        self._conn.execute(
            "UPDATE entities SET times_investigated = times_investigated + 1 WHERE entity=?",
            (entity,),
        )
        self._conn.commit()

    def record_relationship(self, source: str, target: str, port: int, service: str | None = None) -> None:
        """Learn an edge in the network graph: source talked to target over a service.
        Idempotent — repeated calls just bump last_seen and connection_count."""
        source = self.resolve_identity(source)
        target = self.resolve_identity(target)
        now = time.time()
        self._conn.execute(
            """INSERT INTO relationships
                 (source, target, port, service, first_seen, last_seen, connection_count)
               VALUES (?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(source, target, port) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 connection_count=connection_count + 1""",
            (source, target, int(port), service, now, now),
        )
        self._conn.commit()

    def check_topology_drift(self, source: str, target: str, port: int | None = None) -> dict:
        """Deterministic novelty check: is source->target an established baseline, or
        has this source NEVER reached this target before? An unprecedented edge is the
        signature of lateral movement — and it's a hard fact the code hands the agent,
        so the LLM doesn't have to guess whether a connection is normal."""
        source = self.resolve_identity(source)
        target = self.resolve_identity(target)
        if port is None:
            row = self._conn.execute(
                "SELECT * FROM relationships WHERE source=? AND target=? ORDER BY connection_count DESC LIMIT 1",
                (source, target),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM relationships WHERE source=? AND target=? AND port=?",
                (source, target, int(port)),
            ).fetchone()

        known_targets = [
            r["target"]
            for r in self._conn.execute(
                "SELECT DISTINCT target FROM relationships WHERE source=?", (source,)
            ).fetchall()
        ]

        if row:
            return {
                "source": source, "target": target,
                "status": "known_baseline",
                "connection_count": row["connection_count"],
                "note": f"{source} has an established relationship with {target} (seen {row['connection_count']}x).",
            }
        return {
            "source": source, "target": target,
            "status": "UNPRECEDENTED",
            "known_targets_for_source": known_targets,
            "note": (
                f"{source} has NEVER connected to {target} before"
                + (f"; it normally only reaches {known_targets}. This is a topology shift — possible lateral movement."
                   if known_targets else "; no prior relationships are recorded for this source.")
            ),
        }

    # --- statistical baselining ---------------------------------------------

    def record_metric(self, entity: str, name: str, value: float) -> None:
        """Append a numeric observation to an asset's time series (for baselining)."""
        entity = self.resolve_identity(entity)
        self._conn.execute(
            "INSERT INTO metrics (entity, ts, name, value) VALUES (?, ?, ?, ?)",
            (entity, time.time(), name, float(value)),
        )
        self._conn.commit()

    def anomaly(self, entity: str, name: str, current: float) -> dict:
        """Deterministic anomaly score: how many standard deviations is `current`
        from this asset's historical mean for `name`? This is a hard fact for the
        LLM, computed in code — no guessing, no black box, fully explainable.

        Call this BEFORE record_metric so the baseline reflects prior history only."""
        entity = self.resolve_identity(entity)
        rows = self._conn.execute(
            "SELECT value FROM metrics WHERE entity=? AND name=? ORDER BY ts", (entity, name)
        ).fetchall()
        vals = [r["value"] for r in rows]
        n = len(vals)
        if n < 3:
            return {"value": current, "samples": n, "status": "learning",
                    "note": f"Baseline still forming ({n} prior samples) — not enough history "
                            f"for a statistical judgment yet."}
        mean = statistics.fmean(vals)
        sd = statistics.pstdev(vals)
        if sd == 0:
            z = 0.0 if current == mean else 99.0
        else:
            z = (current - mean) / sd
        if z >= 3:
            status, note = "anomalous", (
                f"{current:.0f} is {z:.1f}σ ABOVE this asset's normal ({mean:.0f} avg over "
                f"{n} samples) — a statistically significant spike.")
        elif z <= -3:
            status, note = "quiet", (
                f"{current:.0f} is {abs(z):.1f}σ below normal ({mean:.0f} avg) — unusually quiet.")
        else:
            status, note = "normal", (
                f"{current:.0f} is within normal range for this asset (avg {mean:.0f}, {z:+.1f}σ).")
        return {"value": current, "mean": round(mean, 1), "stdev": round(sd, 1),
                "samples": n, "sigma": round(z, 1), "status": status, "note": note}

    # --- read (the RAG recall) ----------------------------------------------

    def recall(self, entity: str) -> dict:
        """Everything we know about an entity: business seed + observed history +
        prior verdicts (with a disposition tally that drives fast, confident reuse)."""
        entity = self.resolve_identity(entity)   # normalize IP -> stable asset id
        row = self._conn.execute(
            "SELECT * FROM entities WHERE entity=?", (entity,)
        ).fetchone()
        verdicts = self._conn.execute(
            """SELECT ts, disposition, category, threat_score, compromise_confirmed, summary
               FROM verdicts WHERE entity=? ORDER BY ts DESC LIMIT 10""",
            (entity,),
        ).fetchall()
        observations = self._conn.execute(
            "SELECT ts, source, facts FROM observations WHERE entity=? ORDER BY ts DESC LIMIT 5",
            (entity,),
        ).fetchall()

        seed = self._seed.get(entity)
        if not seed:  # /16-style subnet fallback for seeded ranges
            for key, val in self._seed.items():
                if key.endswith("/16") and entity.startswith(key.split(".")[0]):
                    seed = {"matched_range": key, **val}
                    break

        rels = self._conn.execute(
            "SELECT target, service, connection_count FROM relationships WHERE source=? ORDER BY connection_count DESC",
            (entity,),
        ).fetchall()

        disp_tally = Counter(v["disposition"] for v in verdicts)
        return {
            "entity": entity,
            "stable_id": entity,
            "current_ip": self.current_ip(entity),
            "known": row is not None or seed is not None,
            "known_relationships": [
                {"normally_reaches": r["target"], "service": r["service"], "times_seen": r["connection_count"]}
                for r in rels
            ],
            "times_investigated": (row["times_investigated"] if row else 0),
            "first_seen": (row["first_seen"] if row else None),
            "last_seen": (row["last_seen"] if row else None),
            "business_context": seed or "no seeded business context (infer from observations)",
            "prior_disposition_tally": dict(disp_tally),
            "ever_confirmed_compromise": any(v["compromise_confirmed"] for v in verdicts),
            "recent_verdicts": [
                {
                    "disposition": v["disposition"], "category": v["category"],
                    "threat_score": v["threat_score"], "summary": v["summary"],
                }
                for v in verdicts
            ],
            "recent_observations": [
                {"source": o["source"], "facts": json.loads(o["facts"])} for o in observations
            ],
        }

    def stats(self) -> dict:
        e = self._conn.execute("SELECT COUNT(*) c FROM entities").fetchone()["c"]
        v = self._conn.execute("SELECT COUNT(*) c FROM verdicts").fetchone()["c"]
        o = self._conn.execute("SELECT COUNT(*) c FROM observations").fetchone()["c"]
        rel = self._conn.execute("SELECT COUNT(*) c FROM relationships").fetchone()["c"]
        return {"entities": e, "verdicts": v, "observations": o, "relationships": rel, "db": str(self.db_path)}
