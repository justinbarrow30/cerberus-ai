"""Offline validation of the Microsoft Sentinel adapter.

There's no live Sentinel here, so we stand up a fake Azure AD token endpoint and a
fake Log Analytics query endpoint with httpx.MockTransport, then drive the REAL
adapter through it. This proves the OAuth call, the KQL we generate, the Log
Analytics response parsing, and the normalization to our shared shape all line up.
What it canNOT prove: that our table/field choices match a real workspace's schema.

Run:  python test_sentinel.py
"""

import asyncio
import json
import sys

import httpx

import siem.sentinel as sentinel
from siem import get_adapter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CFG = {"siem": {
    "provider": "sentinel", "cloud": "commercial", "table": "SecurityEvent",
    "tenant_id": "tenant-guid", "client_id": "app-guid",
    "client_secret": "shhh", "workspace_id": "ws-guid",
}}

# KQL strings the adapter sends, captured so we can assert we built them correctly.
seen_kql: list[str] = []


def _la(columns, rows):
    """Shape a Log Analytics /query response the way the real API returns it."""
    return {"tables": [{
        "name": "PrimaryResult",
        "columns": [{"name": c, "type": "string"} for c in columns],
        "rows": rows,
    }]}


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "oauth2/v2.0/token" in url:
        assert b"client_credentials" in request.content
        assert b"api.loganalytics.io" in request.content  # commercial scope
        return httpx.Response(200, json={"access_token": "FAKE.JWT", "expires_in": 3600})

    if "/v1/workspaces/" in url and url.endswith("/query"):
        assert request.headers.get("Authorization") == "Bearer FAKE.JWT"
        kql = json.loads(request.content)["query"]
        seen_kql.append(kql)
        if "| take 1" in kql:                        # test_connection probe
            return httpx.Response(200, json=_la(["x"], [["ok"]]))
        if "top 20 by c" in kql:                     # list_recent_sources
            return httpx.Response(200, json=_la(
                ["IpAddress", "c", "targets"],
                [["10.0.0.9", 42, ["DC01", "FILE01"]], ["10.0.0.5", 7, ["WEB01"]]]))
        if "summarize failed=" in kql:               # query_source_activity aggregate
            return httpx.Response(200, json=_la(
                ["failed", "success", "total", "targets"],
                [[40, 2, 42, ["DC01", "FILE01"]]]))
        if "project line=" in kql:                   # query_source_activity samples
            return httpx.Response(200, json=_la(
                ["line"],
                [["2026-09-01 DC01 EventID=4625 from 10.0.0.9 account admin"]]))
        return httpx.Response(200, json=_la([], []))

    return httpx.Response(404, text=f"unexpected {url}")


_real_async_client = httpx.AsyncClient  # capture before we monkeypatch


def _client_factory(*args, **kwargs):
    kwargs["transport"] = httpx.MockTransport(handler)
    return _real_async_client(*args, **kwargs)


async def main() -> int:
    sentinel.httpx.AsyncClient = _client_factory  # inject the fake transport
    a = get_adapter(CFG)
    assert a.__class__.__name__ == "SentinelAdapter", "factory did not route sentinel"

    ok, msg = await a.test_connection()
    assert ok, msg
    print(f"[OK] test_connection -> {msg}")

    sources = await a.list_recent_sources(window_min=10)
    assert sources[0] == {"source": "10.0.0.9", "targets": ["DC01", "FILE01"], "alert_count": 42}, sources
    assert len(sources) == 2
    print(f"[OK] list_recent_sources -> {len(sources)} sources, top={sources[0]['source']}")

    act = await a.query_source_activity("10.0.0.9", window_minutes=60)
    assert act["failed_auth_count"] == 40 and act["successful_auth_count"] == 2, act
    assert act["total_alerts"] == 42
    assert act["targets_contacted"] == ["DC01", "FILE01"]
    assert act["sample_logs"] and "4625" in act["sample_logs"][0]
    assert act["source_ip"] == "10.0.0.9"
    print(f"[OK] query_source_activity -> failed={act['failed_auth_count']} "
          f"success={act['successful_auth_count']} targets={act['targets_contacted']}")

    # KQL sanity: the generated queries must scope by table, time window, and fail condition.
    q = next(k for k in seen_kql if "top 20 by c" in k)
    assert q.startswith("SecurityEvent | where TimeGenerated > ago(10m)"), q
    assert "EventID == 4625" in q and "make_set(Computer, 5)" in q, q
    print(f"[OK] KQL well-formed -> {q[:70]}...")

    # KQL injection guard: a non-IP source must not reach the query literally.
    seen_kql.clear()
    await a.query_source_activity('x" or "1"=="1', window_minutes=5)
    assert all('or "1"' not in k for k in seen_kql), "injection guard failed!"
    print("[OK] injection guard -> malicious source stripped from KQL")

    print("\nAll Sentinel adapter checks passed (against mocked Log Analytics).")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
