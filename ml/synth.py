"""Synthetic behavioral data for training and, crucially, for EVALUATION.

Real labeled attack data is scarce, so to prove the models work we generate a
realistic population of normal entity-behavior and a minority of attack-like
anomalies drawn from recognizable patterns (brute force, lateral spread, off-hours
stealth, blended). The models are trained unsupervised on the normal population and
must then separate held-out anomalies from held-out normals. The labels exist only to
score that separation, never during training.

The distributions deliberately OVERLAP: a fraction of normal hosts are busy and noisy
(a flaky service retrying, a backup job touching many hosts), and the attacks are not
cartoonishly extreme. That overlap is what makes the evaluation honest; perfectly
separable data would prove nothing. Feature order matches ml.features.FEATURE_NAMES.
"""

from __future__ import annotations

import numpy as np


def generate_normal(n: int, seed: int | None = None) -> np.ndarray:
    rng = np.random.default_rng(seed)
    noisy = rng.random(n) < 0.12   # busy-but-benign hosts (retrying services, backup jobs)
    failed = np.where(noisy, rng.poisson(10, n), rng.poisson(2, n)).astype(float)
    success = rng.poisson(6, n).astype(float) + 1
    distinct_targets = 1 + np.where(noisy, rng.poisson(2, n), rng.poisson(0.4, n)).astype(float)
    distinct_rules = 1 + rng.poisson(0.3, n).astype(float)
    total = failed + success + rng.poisson(3, n)
    window = 60.0
    failed_ratio = failed / np.maximum(failed + success, 1)
    events_per_min = total / window
    off_hours = (rng.random(n) < np.where(noisy, 0.30, 0.06)).astype(float)
    new_target_ratio = np.clip(rng.normal(np.where(noisy, 0.15, 0.02), 0.05), 0, 1)
    return np.column_stack([failed, success, distinct_targets, distinct_rules,
                            failed_ratio, events_per_min, off_hours, new_target_ratio])


def generate_anom(n: int, seed: int | None = None) -> np.ndarray:
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        kind = rng.integers(0, 4)
        failed, success = float(rng.poisson(2)), float(rng.poisson(6) + 1)
        dt, dr = 1.0 + rng.poisson(0.4), 1.0 + rng.poisson(0.3)
        off = 1.0 if rng.random() < 0.1 else 0.0
        ntr = float(np.clip(rng.normal(0.02, 0.03), 0, 1))
        if kind == 0:        # brute force: elevated failures and rate
            failed = float(rng.poisson(35) + 15); success = float(rng.poisson(1))
        elif kind == 1:      # lateral spread: fan-out to new targets
            dt = float(rng.poisson(7) + 4); dr = 1.0 + rng.poisson(2)
            ntr = float(np.clip(rng.normal(0.6, 0.2), 0, 1))
        elif kind == 2:      # off-hours stealth, subtle volume
            off = 1.0; failed = float(rng.poisson(8) + 2)
            ntr = float(np.clip(rng.normal(0.4, 0.2), 0, 1))
        else:                # blended campaign
            failed = float(rng.poisson(25) + 8); dt = float(rng.poisson(5) + 2)
            off = 1.0 if rng.random() < 0.6 else 0.0
            ntr = float(np.clip(rng.normal(0.5, 0.2), 0, 1))
        total = failed + success + rng.poisson(5)
        window = 60.0
        fr = failed / max(failed + success, 1)
        epm = total / window
        rows.append([failed, success, dt, dr, fr, epm, off, ntr])
    return np.array(rows, dtype=float)


def generate(n_normal: int = 2400, n_anom: int = 400, seed: int = 7):
    """A labeled mix for quick checks (0 = normal, 1 = anomalous)."""
    Xn, Xa = generate_normal(n_normal, seed), generate_anom(n_anom, seed + 1)
    X = np.vstack([Xn, Xa])
    y = np.concatenate([np.zeros(len(Xn)), np.ones(len(Xa))])
    return X, y
