"""The behavioral feature vector one source (entity) is described by.

These are the dimensions the anomaly models reason over. They are chosen to capture
the three behaviors that matter most for authentication/lateral-movement triage:
brute force (volume + rate + failure ratio), spreading (fan-out + new destinations),
and stealth timing (off-hours). Keep this list and build_features in sync; the models
are trained and scored on exactly this order.
"""

from __future__ import annotations

FEATURE_NAMES = [
    "failed_auths",        # failed authentications in the window
    "successful_auths",    # successful authentications in the window
    "distinct_targets",    # how many hosts this source touched (fan-out)
    "distinct_rules",      # variety of alert rule types triggered
    "failed_ratio",        # failed / (failed + successful)
    "events_per_min",      # activity rate
    "off_hours",           # 1 if the activity is outside business hours
    "new_target_ratio",    # fraction of targets never seen from this source before
]


def build_features(d: dict) -> list[float]:
    """Assemble the feature vector from a normalized SIEM activity dict (or explicit
    feature keys). Missing dimensions default to 0 so it degrades gracefully."""
    failed = float(d.get("failed_auth_count", d.get("failed_auths", 0)) or 0)
    success = float(d.get("successful_auth_count", d.get("successful_auths", 0)) or 0)
    targets = d.get("targets_contacted")
    distinct_targets = float(d.get("distinct_targets", len(targets) if targets is not None else 0) or 0)
    rules = d.get("top_rules")
    distinct_rules = float(d.get("distinct_rules", len(rules) if rules is not None else 0) or 0)
    total = float(d.get("total_alerts", failed + success) or 0)
    window = float(d.get("window_minutes", 60) or 60)
    failed_ratio = failed / (failed + success) if (failed + success) > 0 else 0.0
    events_per_min = total / window if window > 0 else total
    off_hours = float(d.get("off_hours", 0) or 0)
    new_target_ratio = float(d.get("new_target_ratio", 0) or 0)
    return [failed, success, distinct_targets, distinct_rules,
            failed_ratio, events_per_min, off_hours, new_target_ratio]
