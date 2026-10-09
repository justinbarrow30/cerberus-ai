"""Evaluate the anomaly ensemble on the LANL auth logs with real red-team labels.

Unlike ml/evaluate.py (synthetic on both sides, which only validates the method), this
measures the models on real enterprise authentication traffic with real attacks: the
Los Alamos "Comprehensive Multi-Source Cyber-Security Events" dataset, auth.txt plus
redteam.txt. Get it (and accept the license) at https://csr.lanl.gov/data/cyber1/.

Methodology:
  * Bucket authentications into per-source-computer time windows (default 1 hour).
  * Aggregate the SAME behavioral features the model uses (ml/features.py).
  * Label a window malicious if it contains a red-team event (matched on
    time + computer pair + user against redteam.txt).
  * Train the ensemble UNSUPERVISED on benign windows only, then score held-out
    benign + all malicious windows and report ROC-AUC, PR-AUC, precision/recall.

Usage:
    python -m ml.eval_lanl --auth auth.txt.gz --redteam redteam.txt
    python -m ml.eval_lanl --auth auth.txt.gz --redteam redteam.txt --limit 20000000

auth.txt line:  time,srcUser@dom,dstUser@dom,srcComp,dstComp,authType,logonType,orient,success
redteam line:   time,user@dom,srcComp,dstComp
"""

from __future__ import annotations

import argparse
import gzip
import sys
from collections import defaultdict

import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

from .anomaly import AnomalyEnsemble, _torch
from .features import FEATURE_NAMES

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

WINDOW_SECONDS = 3600
THRESHOLD = 0.95


def _open(path: str):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.endswith(".gz") \
        else open(path, "r", encoding="utf-8", errors="replace")


def _load_redteam(path: str) -> set:
    rt = set()
    with _open(path) as f:
        for line in f:
            p = line.strip().split(",")
            if len(p) >= 4:
                rt.add((p[0], p[1], p[2], p[3]))   # time, user, srcComp, dstComp
    return rt


def _aggregate(auth_path: str, rt: set, limit: int | None):
    """Stream auth.txt into per-(source computer, time window) behavioral buckets."""
    agg: dict = {}
    seen_dst = defaultdict(set)   # srcComp -> dst computers seen so far (for new-target ratio)
    n = 0
    with _open(auth_path) as f:
        for line in f:
            n += 1
            if limit and n > limit:
                break
            p = line.rstrip("\n").split(",")
            if len(p) < 9:
                continue
            try:
                t = int(p[0])
            except ValueError:
                continue
            su, du, src, dst, atype, success = p[1], p[2], p[3], p[4], p[5], p[8]
            win = t // WINDOW_SECONDS
            key = (src, win)
            b = agg.get(key)
            if b is None:
                hour = (win * WINDOW_SECONDS % 86400) // 3600
                b = agg[key] = {"failed": 0, "success": 0, "dsts": set(), "new": set(),
                                "types": set(), "total": 0, "off": 1 if (hour < 6 or hour >= 20) else 0,
                                "mal": False}
            b["total"] += 1
            b["types"].add(atype)
            if success.lower().startswith("succ"):
                b["success"] += 1
            else:
                b["failed"] += 1
            if dst not in seen_dst[src]:
                seen_dst[src].add(dst)
                b["new"].add(dst)
            b["dsts"].add(dst)
            if (p[0], du, src, dst) in rt or (p[0], su, src, dst) in rt:
                b["mal"] = True
    return agg, n


def _features(agg) -> tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    for b in agg.values():
        fa, ok, tot = b["failed"], b["success"], b["total"]
        dsts = len(b["dsts"])
        X.append([
            float(fa), float(ok), float(dsts), float(len(b["types"])),
            fa / (fa + ok) if (fa + ok) else 0.0,
            tot / (WINDOW_SECONDS / 60.0),
            float(b["off"]),
            (len(b["new"]) / dsts) if dsts else 0.0,
        ])
        y.append(1 if b["mal"] else 0)
    return np.array(X, dtype=float), np.array(y, dtype=int)


def _report(y, scores, name):
    pred = (scores >= THRESHOLD).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    print(f"{name:<18}{roc_auc_score(y, scores):>9.3f}{average_precision_score(y, scores):>9.3f}"
          f"{p:>11.3f}{r:>9.3f}{f:>7.3f}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate the anomaly ensemble on LANL auth + redteam.")
    ap.add_argument("--auth", required=True, help="path to auth.txt or auth.txt.gz")
    ap.add_argument("--redteam", required=True, help="path to redteam.txt")
    ap.add_argument("--limit", type=int, default=None, help="only read the first N auth lines")
    args = ap.parse_args()

    print(f"Loading red-team labels from {args.redteam}...")
    rt = _load_redteam(args.redteam)
    print(f"  {len(rt)} red-team events")
    print(f"Streaming {args.auth} into {WINDOW_SECONDS // 3600}h per-source windows...")
    agg, n = _aggregate(args.auth, rt, args.limit)
    X, y = _features(agg)
    mal = int(y.sum())
    print(f"  {n:,} auth lines -> {len(X):,} windows, {mal} malicious")
    if mal == 0:
        print("No malicious windows in this slice. Use a larger --limit; red-team activity")
        print("starts after the first days, so a small head of the file may contain none.")
        return 1

    ben = X[y == 0]
    rng = np.random.default_rng(7)
    idx = rng.permutation(len(ben))
    cut = int(len(ben) * 0.8)
    Xtr, Xte_ben = ben[idx[:cut]], ben[idx[cut:]]

    print(f"Training on {len(Xtr):,} benign windows "
          f"(Isolation Forest{' + autoencoder' if _torch() else ''})...")
    ens = AnomalyEnsemble().fit(Xtr)

    Xte = np.vstack([Xte_ben, X[y == 1]])
    yte = np.concatenate([np.zeros(len(Xte_ben)), np.ones(mal)])
    sc = ens.score(Xte)

    print(f"\nEvaluated on {len(Xte_ben):,} held-out benign + {mal} malicious windows "
          f"(threshold {THRESHOLD:.0%})\n")
    print(f"{'Model':<18}{'ROC-AUC':>9}{'PR-AUC':>9}{'Precision':>11}{'Recall':>9}{'F1':>7}")
    print("-" * 63)
    _report(yte, sc["iso_pct"], "Isolation Forest")
    if _torch():
        _report(yte, sc["ae_pct"], "Autoencoder")
    _report(yte, sc["ensemble"], "Ensemble")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
