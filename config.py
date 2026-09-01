"""Runtime configuration for CerberusAI.

Loads config.json if present (written by the setup wizard), otherwise falls back
to environment variables so the existing lab keeps working with no config file.
This is what lets a user point the tool at THEIR SIEM without editing code.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("CERBERUS_CONFIG", Path(__file__).resolve().parent / "config.json"))

# Default field mapping for the OpenSearch family (Wazuh / Elastic / Security Onion).
# A different SIEM/schema overrides these in its saved config.
_WAZUH_DEFAULT_FIELDS = {
    "source_ip": "data.srcip",   # field holding the source IP
    "target": "agent.name",      # field holding the monitored host (stable identity)
    "raw_log": "full_log",       # the raw log line
    "timestamp": "@timestamp",
    "level": "rule.level",
    "rule_desc": "rule.description",
    "success_phrase": "Accepted",       # full_log substring meaning "login succeeded"
    "failed_phrase": "Failed password",  # full_log substring meaning "auth failed"
}


def _from_env() -> dict:
    """Reconstruct config from env vars (backwards-compatible with the lab setup)."""
    return {
        "siem": {
            "provider": "opensearch",
            "url": os.environ.get("INDEXER_URL", "https://localhost:9200"),
            "user": os.environ.get("INDEXER_USER", "admin"),
            "password": os.environ.get("INDEXER_PASS", "SecretPassword"),
            "verify_tls": os.environ.get("INDEXER_VERIFY_TLS", "false").lower() == "true",
            "index": os.environ.get("INDEXER_INDEX", "wazuh-alerts-*"),
            "min_level": int(os.environ.get("MIN_LEVEL", "5")),
            "fields": dict(_WAZUH_DEFAULT_FIELDS),
        },
        "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY"),
        "model": os.environ.get("CERBERUS_MODEL", "claude-opus-5"),
    }


def load_config() -> dict:
    if CONFIG_PATH.exists():
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        # Fill any missing field-map keys with the OpenSearch defaults.
        siem = cfg.setdefault("siem", {})
        fields = siem.setdefault("fields", {})
        for k, v in _WAZUH_DEFAULT_FIELDS.items():
            fields.setdefault(k, v)
        return cfg
    return _from_env()


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def is_configured() -> bool:
    """True once a real config exists (used by the setup wizard to gate the app)."""
    return CONFIG_PATH.exists()
