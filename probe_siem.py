"""Point the configured SIEM adapter at your real SIEM and print what it sees.

This is the validation tool: it doesn't just check that auth works, it shows you the
NORMALIZED data the agent will reason over — so you can confirm the field mapping is
actually right (source IPs populated, failed/successful counts sane, targets present).

    python probe_siem.py                 # uses the last 60 minutes
    python probe_siem.py --window 10080  # last 7 days (use this for historical/sample data)
    python probe_siem.py --source 10.0.0.9 --window 1440

Reads config.json (the same file the setup wizard writes), so configure the SIEM in the
GUI first, or run it against whatever provider you've saved.
"""

import argparse
import asyncio
import json
import sys

from config import load_config
from siem import get_adapter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _hr(title: str) -> None:
    print(f"\n{'=' * 4} {title} {'=' * (60 - len(title))}")


async def main(window: int, source: str | None) -> int:
    cfg = load_config()
    provider = (cfg.get("siem", {}).get("provider") or "?")
    print(f"Provider: {provider}   window: {window} min")

    try:
        adapter = get_adapter(cfg)
    except Exception as e:
        print(f"[FAIL] could not build adapter: {e}")
        return 1

    _hr("test_connection")
    ok, msg = await adapter.test_connection()
    print(f"{'[OK]' if ok else '[FAIL]'} {msg}")
    if not ok:
        print("\nFix the connection above before probing further.")
        return 1

    _hr(f"list_recent_sources(window_min={window})")
    sources = await adapter.list_recent_sources(window_min=window)
    if not sources:
        print("No sources in this window. If your data is historical (e.g. Sentinel")
        print("Training-Lab sample data), widen it, e.g. --window 10080 for 7 days.")
        return 0
    for s in sources[:10]:
        print(f"  {s.get('source'):<22} alerts={s.get('alert_count')}  targets={s.get('targets')}")

    probe_src = source or sources[0]["source"]
    _hr(f"query_source_activity(source={probe_src!r}, window_minutes={window})")
    act = await adapter.query_source_activity(probe_src, window_minutes=window)
    print(json.dumps(act, indent=2, default=str))

    _hr("field-mapping sanity")
    checks = [
        ("source_ip populated", bool(act.get("source_ip"))),
        ("failed/successful counts are numbers",
         isinstance(act.get("failed_auth_count"), int) and isinstance(act.get("successful_auth_count"), int)),
        ("at least one sample log", bool(act.get("sample_logs"))),
        ("targets_contacted present", isinstance(act.get("targets_contacted"), list)),
    ]
    for label, good in checks:
        print(f"  {'[OK]  ' if good else '[WARN]'} {label}")
    if not act.get("sample_logs"):
        print("\n  Note: empty sample_logs usually means the table/field names don't match")
        print("  your data. Adjust the table or siem.fields in config.json and re-run.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Probe the configured SIEM adapter against the real SIEM.")
    ap.add_argument("--window", type=int, default=60, help="lookback window in minutes (default 60)")
    ap.add_argument("--source", help="probe this specific source instead of the busiest one")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(main(args.window, args.source)))
