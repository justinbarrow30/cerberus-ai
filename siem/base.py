"""SIEM adapter interface + factory.

A SIEM adapter returns NORMALIZED data so the brain is SIEM-agnostic:

  test_connection()            -> (ok: bool, message: str)
  list_recent_sources(window)  -> [ {source, targets:[..], alert_count} ]
  query_source_activity(src, window) -> {
        source_ip, window_minutes, total_alerts,
        failed_auth_count, successful_auth_count,
        top_rules:[{rule,count}], sample_logs:[..], targets_contacted:[..] }

Adding a SIEM = subclass this and register it in `get_adapter`. Nothing else changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class SIEMAdapter(ABC):
    def __init__(self, siem_config: dict):
        self.cfg = siem_config
        self.fields = siem_config.get("fields", {})

    @abstractmethod
    async def test_connection(self) -> tuple[bool, str]:
        """Read-only reachability + auth check for the setup wizard."""

    @abstractmethod
    async def list_recent_sources(self, window_min: int = 10) -> list[dict]:
        """Distinct source identities seen recently, with the hosts they contacted."""

    @abstractmethod
    async def query_source_activity(self, source: str, window_minutes: int = 60) -> dict:
        """Normalized authentication activity for one source over a time window."""


def get_adapter(config: dict) -> SIEMAdapter:
    """Build the adapter for the configured provider."""
    siem = config.get("siem", {})
    provider = (siem.get("provider") or "opensearch").lower()
    if provider in ("opensearch", "elasticsearch", "wazuh", "elastic", "security-onion", "securityonion"):
        from .opensearch import OpenSearchAdapter
        return OpenSearchAdapter(siem)
    if provider in ("sentinel", "microsoft-sentinel", "azure-sentinel"):
        from .sentinel import SentinelAdapter
        return SentinelAdapter(siem)
    raise ValueError(
        f"Unsupported SIEM provider '{provider}'. Supported: opensearch (Wazuh / Elastic / "
        f"Security Onion) and sentinel (Microsoft Sentinel). Splunk & CrowdStrike LogScale "
        f"are next — add an adapter in siem/."
    )
