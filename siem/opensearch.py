"""OpenSearch / Elasticsearch adapter — covers Wazuh, Elastic Security, Security Onion.

All three store alerts in an Elasticsearch-compatible index, so one adapter handles
them via a configurable index pattern + field map (see config.py). This is the same
read-only query logic the lab used, now parameterized so it points at ANY such SIEM.
"""

from __future__ import annotations

import httpx

from config import _WAZUH_DEFAULT_FIELDS

from .base import SIEMAdapter


class OpenSearchAdapter(SIEMAdapter):
    def __init__(self, siem_config: dict):
        super().__init__(siem_config)
        # Fill any missing field-map keys with the OpenSearch defaults so the adapter
        # is safe to build from a partial config (e.g. the setup wizard's test payload).
        self.fields = {**_WAZUH_DEFAULT_FIELDS, **(siem_config.get("fields") or {})}
        self.url = siem_config["url"].rstrip("/")
        self.auth = (siem_config.get("user", ""), siem_config.get("password", ""))
        self.verify = bool(siem_config.get("verify_tls", False))
        self.index = siem_config.get("index", "wazuh-alerts-*")
        self.min_level = int(siem_config.get("min_level", 5))
        f = self.fields
        self.f_src = f["source_ip"]
        self.f_tgt = f["target"]
        self.f_raw = f["raw_log"]
        self.f_ts = f["timestamp"]
        self.f_lvl = f["level"]
        self.f_rule = f["rule_desc"]
        self.ok_phrase = f["success_phrase"]
        self.bad_phrase = f["failed_phrase"]

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(verify=self.verify, timeout=30.0)

    async def _search(self, body: dict) -> dict:
        async with self._client() as c:
            r = await c.post(f"{self.url}/{self.index}/_search", json=body, auth=self.auth)
            r.raise_for_status()
            return r.json()

    async def test_connection(self) -> tuple[bool, str]:
        try:
            async with self._client() as c:
                r = await c.get(f"{self.url}/", auth=self.auth)
        except httpx.HTTPError as e:
            return False, f"Could not reach SIEM at {self.url}: {e}"
        if r.status_code == 401:
            return False, "Authentication failed — check the username/password or API token."
        if r.status_code != 200:
            return False, f"SIEM returned HTTP {r.status_code}."
        ver = (r.json().get("version", {}) or {}).get("number", "?")
        # Confirm the alert index actually exists / is queryable.
        try:
            await self._search({"size": 0, "query": {"match_all": {}}})
        except httpx.HTTPError:
            return False, f"Connected (v{ver}) but index '{self.index}' is not queryable — check the index pattern."
        return True, f"Connected to OpenSearch/Elasticsearch v{ver}, index '{self.index}' OK."

    async def list_recent_sources(self, window_min: int = 10) -> list[dict]:
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {self.f_lvl: {"gte": self.min_level}}},
                {"range": {self.f_ts: {"gte": f"now-{window_min}m"}}},
                {"exists": {"field": self.f_src}},
            ]}},
            "aggs": {"sources": {"terms": {"field": self.f_src, "size": 20},
                                 "aggs": {"targets": {"terms": {"field": self.f_tgt, "size": 5}}}}},
        }
        d = await self._search(body)
        buckets = d.get("aggregations", {}).get("sources", {}).get("buckets", [])
        return [
            {"source": b["key"],
             "targets": [t["key"] for t in b.get("targets", {}).get("buckets", [])],
             "alert_count": b["doc_count"]}
            for b in buckets
        ]

    async def query_source_activity(self, source: str, window_minutes: int = 60) -> dict:
        body = {
            "size": 3,
            "sort": [{self.f_ts: "desc"}],
            "_source": [self.f_raw, self.f_rule],
            "query": {"bool": {"filter": [
                {"match_phrase": {self.f_raw: source}},
                {"range": {self.f_ts: {"gte": f"now-{int(window_minutes)}m"}}},
            ]}},
            "aggs": {
                "top_rules": {"terms": {"field": self.f_rule, "size": 8}},
                "successful_auths": {"filter": {"match_phrase": {self.f_raw: self.ok_phrase}}},
                "failed_auths": {"filter": {"match_phrase": {self.f_raw: self.bad_phrase}}},
                "targets": {"terms": {"field": self.f_tgt, "size": 10}},
            },
        }
        d = await self._search(body)
        aggs = d.get("aggregations", {})

        def _nested(src: dict, dotted: str):
            cur = src
            for part in dotted.split("."):
                if not isinstance(cur, dict):
                    return None
                cur = cur.get(part)
            return cur

        return {
            "source_ip": source,
            "window_minutes": window_minutes,
            "total_alerts": d.get("hits", {}).get("total", {}).get("value", 0),
            "failed_auth_count": aggs.get("failed_auths", {}).get("doc_count", 0),
            "successful_auth_count": aggs.get("successful_auths", {}).get("doc_count", 0),
            "top_rules": [{"rule": b["key"], "count": b["doc_count"]}
                          for b in aggs.get("top_rules", {}).get("buckets", [])],
            "sample_logs": [_nested(h.get("_source", {}), self.f_raw) or ""
                            for h in d.get("hits", {}).get("hits", [])],
            "targets_contacted": [b["key"] for b in aggs.get("targets", {}).get("buckets", [])],
        }
