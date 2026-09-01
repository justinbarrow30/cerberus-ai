"""Microsoft Sentinel adapter — reads a Log Analytics workspace via KQL.

Auth is Azure AD app (client-credentials): tenant + client id/secret get a token
for the Log Analytics API, then we run KQL against the workspace. Commercial and
Azure **Government** clouds are both supported (different endpoints).

NOT yet validated against a live workspace — the KQL construction and response
parsing are unit-tested with recorded Log Analytics payloads (see tests), but the
real OAuth + query round-trip needs a real Sentinel to confirm field/table choices.

Table presets map Sentinel's schema onto our normalized shape. Default is
SecurityEvent (Windows 4624/4625); SigninLogs (Entra ID sign-ins) is also built in.
Override the table/fields in config.json under siem if your data lives elsewhere.
"""

from __future__ import annotations

import re
import time

import httpx

from .base import SIEMAdapter

_CLOUDS = {
    "commercial": {"login": "https://login.microsoftonline.com", "api": "https://api.loganalytics.io"},
    "government": {"login": "https://login.microsoftonline.us", "api": "https://api.loganalytics.us"},
}

# How each table exposes the fields our agent needs.
_PRESETS = {
    "SecurityEvent": {  # Windows Security events (4624 success / 4625 failure)
        "src": "IpAddress", "tgt": "Computer", "ts": "TimeGenerated",
        "fail": "EventID == 4625", "ok": "EventID == 4624",
        "sample": 'strcat(tostring(TimeGenerated), " ", Computer, " EventID=", tostring(EventID), '
                  '" from ", IpAddress, " account ", Account)',
    },
    "SigninLogs": {     # Entra ID (Azure AD) interactive sign-ins
        "src": "IPAddress", "tgt": "ResourceDisplayName", "ts": "TimeGenerated",
        "fail": "ResultType != 0", "ok": "ResultType == 0",
        "sample": 'strcat(tostring(TimeGenerated), " signin ", UserPrincipalName, " from ", IPAddress, '
                  '" result=", tostring(ResultType))',
    },
}

_SAFE = re.compile(r"^[0-9a-fA-F:.\-]{1,64}$")   # source values we allow into KQL literally


class SentinelAdapter(SIEMAdapter):
    def __init__(self, siem_config: dict):
        super().__init__(siem_config)
        self.tenant = siem_config.get("tenant_id", "")
        self.client_id = siem_config.get("client_id", "")
        self.client_secret = siem_config.get("client_secret", "")
        self.workspace = siem_config.get("workspace_id", "")
        self.cloud = _CLOUDS.get((siem_config.get("cloud") or "commercial").lower(), _CLOUDS["commercial"])
        self.table = siem_config.get("table") or "SecurityEvent"
        self.p = {**_PRESETS.get(self.table, _PRESETS["SecurityEvent"]), **(siem_config.get("fields") or {})}
        self._token = None
        self._token_exp = 0.0

    async def _bearer(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.post(
                f"{self.cloud['login']}/{self.tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": f"{self.cloud['api']}/.default",
                },
            )
            r.raise_for_status()
            j = r.json()
        self._token = j["access_token"]
        self._token_exp = time.time() + int(j.get("expires_in", 3600))
        return self._token

    async def _kql(self, query: str) -> list[dict]:
        token = await self._bearer()
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(
                f"{self.cloud['api']}/v1/workspaces/{self.workspace}/query",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"query": query},
            )
            r.raise_for_status()
            data = r.json()
        tables = data.get("tables", [])
        if not tables:
            return []
        t = tables[0]
        cols = [c["name"] for c in t.get("columns", [])]
        return [dict(zip(cols, row)) for row in t.get("rows", [])]

    async def test_connection(self) -> tuple[bool, str]:
        for field in ("tenant_id", "client_id", "client_secret", "workspace_id"):
            if not self.cfg.get(field):
                return False, f"Missing required field: {field}."
        try:
            await self._bearer()
        except httpx.HTTPError as e:
            return False, f"Azure AD auth failed — check tenant / client id / secret ({e})."
        try:
            rows = await self._kql(f"{self.table} | take 1")
        except httpx.HTTPError as e:
            return False, f"Authenticated, but querying '{self.table}' failed — check the workspace id / table ({e})."
        return True, f"Connected to Sentinel workspace, table '{self.table}' reachable ({len(rows)} sample row)."

    async def list_recent_sources(self, window_min: int = 10) -> list[dict]:
        p = self.p
        kql = (
            f"{self.table} | where {p['ts']} > ago({int(window_min)}m) | where {p['fail']} "
            f"| where isnotempty({p['src']}) "
            f"| summarize c=count(), targets=make_set({p['tgt']}, 5) by {p['src']} "
            f"| top 20 by c desc"
        )
        rows = await self._kql(kql)
        return [
            {"source": r.get(p["src"]),
             "targets": r.get("targets") or [],
             "alert_count": r.get("c", 0)}
            for r in rows if r.get(p["src"])
        ]

    async def query_source_activity(self, source: str, window_minutes: int = 60) -> dict:
        p = self.p
        src = source if _SAFE.match(source or "") else ""   # refuse anything non-IP-ish into KQL
        w = int(window_minutes)
        agg = await self._kql(
            f'{self.table} | where {p["ts"]} > ago({w}m) | where {p["src"]} == "{src}" '
            f'| summarize failed=countif({p["fail"]}), success=countif({p["ok"]}), '
            f'total=count(), targets=make_set({p["tgt"]}, 10)'
        )
        samples = await self._kql(
            f'{self.table} | where {p["ts"]} > ago({w}m) | where {p["src"]} == "{src}" '
            f'| top 3 by {p["ts"]} desc | project line={p["sample"]}'
        )
        a = agg[0] if agg else {}
        failed, success = a.get("failed", 0) or 0, a.get("success", 0) or 0
        return {
            "source_ip": source,
            "window_minutes": window_minutes,
            "total_alerts": a.get("total", 0) or 0,
            "failed_auth_count": failed,
            "successful_auth_count": success,
            "top_rules": [
                {"rule": f"{self.table}: failed authentication", "count": failed},
                {"rule": f"{self.table}: successful authentication", "count": success},
            ],
            "sample_logs": [r.get("line", "") for r in samples],
            "targets_contacted": a.get("targets") or [],
        }
