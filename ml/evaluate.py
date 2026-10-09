"""Train on normal behavior, then measure how well each model flags held-out attacks.

This is the proof the anomaly layer works. We fit the ensemble unsupervised on normal
data only, then score a held-out mix of normal + synthetic attacks and report, per
model and for the ensemble: ROC-AUC, PR-AUC, and precision/recall/F1 at a 95th-
percentile threshold (flag anything more anomalous than 95% of normal behavior). It
also saves an ROC curve to docs/ml_roc.png and prints an example explanation.

    python -m ml.evaluate
"""

from __future__ import annotations

import os
import sys

import numpy as np
from sklearn.metrics import (average_precision_score, precision_recall_fscore_support,
                             roc_auc_score, roc_curve)

from .anomaly import AnomalyEnsemble, _torch
from .features import FEATURE_NAMES
from .synth import generate_anom, generate_normal

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

THRESHOLD = 0.95   # flag samples above the 95th percentile of normal behavior


def _metrics(y, s):
    pred = (s >= THRESHOLD).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    return {"roc_auc": roc_auc_score(y, s), "pr_auc": average_precision_score(y, s),
            "precision": p, "recall": r, "f1": f}


def main() -> int:
    rng_seed = 7
    Xn = generate_normal(2400, rng_seed)
    Xa = generate_anom(500, rng_seed + 1)
    cut = int(len(Xn) * 0.8)
    Xn_tr, Xn_te = Xn[:cut], Xn[cut:]

    have_ae = _torch() is not None
    print(f"Training ensemble on {len(Xn_tr)} normal samples "
          f"(Isolation Forest{' + autoencoder' if have_ae else ', autoencoder unavailable'})...")
    ens = AnomalyEnsemble().fit(Xn_tr)

    X_te = np.vstack([Xn_te, Xa])
    y = np.concatenate([np.zeros(len(Xn_te)), np.ones(len(Xa))])
    sc = ens.score(X_te)

    models = [("Isolation Forest", sc["iso_pct"])]
    if have_ae:
        models.append(("Autoencoder", sc["ae_pct"]))
    models.append(("Ensemble", sc["ensemble"]))

    print(f"\nEvaluated on {len(Xn_te)} held-out normal + {len(Xa)} attack samples "
          f"(threshold = {THRESHOLD:.0%} percentile)\n")
    print(f"{'Model':<18}{'ROC-AUC':>9}{'PR-AUC':>9}{'Precision':>11}{'Recall':>9}{'F1':>7}")
    print("-" * 63)
    for name, s in models:
        m = _metrics(y, s)
        print(f"{name:<18}{m['roc_auc']:>9.3f}{m['pr_auc']:>9.3f}"
              f"{m['precision']:>11.3f}{m['recall']:>9.3f}{m['f1']:>7.3f}")

    _plot_roc(y, models)

    # Example explanation on the most anomalous attack sample.
    idx = int(np.argmax(sc["ensemble"][len(Xn_te):])) + len(Xn_te)
    top = ens.explain(X_te[idx], k=3)
    print(f"\nExample: a flagged attack scored {sc['ensemble'][idx]:.0%} anomalous. Top drivers:")
    for t in top:
        print(f"  - {t['feature']:<18} value={t['value']:<8} contribution={t['contribution']:+.3f}")
    return 0


def _plot_roc(y, models) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    fig, ax = plt.subplots(figsize=(6, 5))
    for name, s in models:
        fpr, tpr, _ = roc_curve(y, s)
        ax.plot(fpr, tpr, linewidth=2, label=f"{name} (AUC {roc_auc_score(y, s):.3f})")
    ax.plot([0, 1], [0, 1], "--", color="#bbb", linewidth=1)
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("CerberusAI anomaly detection: ROC")
    ax.legend(loc="lower right", frameon=False)
    fig.tight_layout()
    out = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "ml_roc.png")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fig.savefig(out, dpi=160)
    print(f"\nSaved ROC curve to {out}")


if __name__ == "__main__":
    raise SystemExit(main())
