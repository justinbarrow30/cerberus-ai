"""SIEM adapters — the layer that lets CerberusAI talk to ANY SIEM.

The agent/poller only ever use the SIEMAdapter interface (base.py). Each SIEM gets
one adapter that translates its API + schema into the normalized shape the brain
expects. Ship with OpenSearch (Wazuh / Elastic / Security Onion); Splunk, Sentinel,
QRadar, etc. are added by writing another adapter — the brain never changes.
"""

from .base import SIEMAdapter, get_adapter

__all__ = ["SIEMAdapter", "get_adapter"]
