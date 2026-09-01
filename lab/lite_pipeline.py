"""LITE live-fire demo — no Docker, no SIEM required.

Simulates a security log stream (benign traffic plus a scripted SSH brute-force
burst) and pipes each new event through the CerberusAI triage engine in real time,
streaming structured results to the console and to outputs/live_triage.jsonl.

This exists so you can see the *pipeline* — stream in, triage, structured out —
working immediately, before standing up the full Wazuh stack (see README.md).

Run from the repo root:
    python lab/lite_pipeline.py
    python lab/lite_pipeline.py --delay 0.5 --rounds 3

Needs ANTHROPIC_API_KEY in the environment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make the repo root importable when run as `python lab/lite_pipeline.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import triage  # noqa: E402

# Windows consoles default to cp1252; force UTF-8 so any character in a model
# summary prints instead of crashing the stream.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

OUTFILE = Path(__file__).resolve().parent.parent / "outputs" / "live_triage.jsonl"

BENIGN = [
    'nginx: {ip} - - "GET /images/logo.png HTTP/1.1" 200 20481',
    'nginx: {ip} - - "GET /about HTTP/1.1" 200 3120',
    'sshd[{pid}]: Accepted publickey for deploy from {ip} port {port} ssh2',
    'sudo: pam_unix(sudo:session): session opened for user root by deploy(uid=1001)',
]

INJECTION = 'nginx: {ip} - - "GET /index.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 512'


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")


def rand_ip() -> str:
    return f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def event_stream(rounds: int):
    """Yield raw log lines: mostly benign, with a brute-force burst each round."""
    for _ in range(rounds):
        for _ in range(random.randint(1, 2)):
            tmpl = random.choice(BENIGN)
            yield f"{ts()} host " + tmpl.format(
                ip=rand_ip(), pid=random.randint(1000, 9999), port=random.randint(40000, 60000)
            )
        # A brute-force burst from a single source, ending in success.
        attacker = rand_ip()
        for _ in range(random.randint(3, 4)):
            yield (f"{ts()} target-host sshd[{random.randint(1000,9999)}]: "
                   f"Failed password for root from {attacker} port {random.randint(40000,60000)} ssh2")
        yield (f"{ts()} target-host sshd[{random.randint(1000,9999)}]: "
               f"Accepted password for root from {attacker} port {random.randint(40000,60000)} ssh2")
        # An injection attempt.
        yield f"{ts()} web01 " + INJECTION.format(ip=rand_ip())


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between events")
    ap.add_argument("--rounds", type=int, default=2, help="how many attack rounds to simulate")
    args = ap.parse_args()

    OUTFILE.parent.mkdir(exist_ok=True)
    print(f"Streaming simulated events -> triage. Writing {OUTFILE}\n", file=sys.stderr)

    with OUTFILE.open("a", encoding="utf-8") as sink:
        for raw in event_stream(args.rounds):
            result = await triage(raw)
            record = {"received_at": datetime.now(timezone.utc).isoformat(),
                      "raw_log": raw, **result.model_dump()}
            record["category"] = result.category.value
            sink.write(json.dumps(record) + "\n")
            sink.flush()

            flag = "[CRIT]" if result.threat_score >= 7 else ("[WARN]" if result.threat_score >= 4 else "[ ok ]")
            print(f"{flag} [{result.threat_score:>2}/10] {result.category.value:<20} {result.summary}")
            await asyncio.sleep(args.delay)


if __name__ == "__main__":
    asyncio.run(main())
