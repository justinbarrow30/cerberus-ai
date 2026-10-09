"""Train the anomaly ensemble and save it to ml/models/.

By default it trains on the real behavior CerberusAI has logged (ml/behavior_log.jsonl,
written by the agent as it investigates). Until enough real traffic has accumulated,
pass --bootstrap to train on synthetic normal behavior so the signal works on day one;
retrain on real data once the log is large enough.

    python -m ml.train               # train on logged real behavior
    python -m ml.train --bootstrap   # cold-start on synthetic normal behavior
"""

from __future__ import annotations

import argparse
import json
import sys

import numpy as np

from .anomaly import AnomalyEnsemble
from .features import FEATURE_NAMES
from .runtime import LOG_PATH, MODELS_DIR
from .synth import generate_normal

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MIN_ROWS = 200   # below this, a learned baseline is too thin to trust


def _load_log() -> np.ndarray:
    rows = []
    if LOG_PATH.exists():
        for line in LOG_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                rows.append([float(d.get(k, 0)) for k in FEATURE_NAMES])
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    return np.array(rows, dtype=float) if rows else np.empty((0, len(FEATURE_NAMES)))


def main() -> int:
    ap = argparse.ArgumentParser(description="Train the CerberusAI anomaly ensemble.")
    ap.add_argument("--bootstrap", action="store_true",
                    help="train on synthetic normal behavior (cold start)")
    args = ap.parse_args()

    if args.bootstrap:
        X = generate_normal(2400, seed=7)
        src = "synthetic normal behavior (bootstrap)"
    else:
        X = _load_log()
        src = f"{len(X)} logged observations ({LOG_PATH})"
        if len(X) < MIN_ROWS:
            print(f"Only {len(X)} logged observations; need at least {MIN_ROWS}.")
            print("Run with --bootstrap to cold-start on synthetic data, then retrain later.")
            return 1

    print(f"Training ensemble on {src}...")
    ens = AnomalyEnsemble().fit(X)
    ens.save(str(MODELS_DIR))
    print(f"Saved model to {MODELS_DIR}"
          + ("  (Isolation Forest + autoencoder)" if ens.ae is not None else "  (Isolation Forest only)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
