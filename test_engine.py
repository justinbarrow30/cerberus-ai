"""Direct-call harness for the triage engine (no MCP transport involved).

This is the fastest way to validate parsing quality and iterate on the schema /
system prompt. Run it against the bundled sample logs:

    python test_engine.py
    python test_engine.py samples/auth_logs.txt

Requires ANTHROPIC_API_KEY in the environment (or an `ant auth login` profile).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from engine import triage


def load_logs(path: str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln for ln in lines if ln.strip()]


async def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/auth_logs.txt"
    logs = load_logs(path)
    print(f"Triaging {len(logs)} event(s) from {path}\n", file=sys.stderr)

    for raw in logs:
        result = await triage(raw)
        print("-" * 72)
        print(f"LOG      : {raw}")
        print(f"SCORE    : {result.threat_score}/10   "
              f"EXPLOIT: {result.is_active_exploit}   "
              f"CATEGORY: {result.category.value}")
        print(f"SUMMARY  : {result.summary}")
        if result.indicators:
            print(f"IOCs     : {', '.join(result.indicators)}")
        for i, action in enumerate(result.recommended_triage_actions, 1):
            print(f"ACTION {i} : {action}")
    print("-" * 72)


if __name__ == "__main__":
    asyncio.run(main())
