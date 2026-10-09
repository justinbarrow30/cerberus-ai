"""Runtime glue between the agent and the anomaly ensemble.

Everything here is best-effort and optional: if the ML dependencies or a trained
model are not present, score_activity returns None and CerberusAI runs exactly as it
did before. The agent calls score_activity to get an extra evidence signal, and
log_activity to append the observed behavior for later retraining on real data.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .features import FEATURE_NAMES, build_features

MODELS_DIR = Path(os.environ.get("CERBERUS_ML_MODELS", Path(__file__).resolve().parent / "models"))
LOG_PATH = Path(os.environ.get("CERBERUS_ML_LOG", Path(__file__).resolve().parent / "behavior_log.jsonl"))
THRESHOLD = 0.95

_ENSEMBLE = None
_TRIED = False


def _ensemble():
    global _ENSEMBLE, _TRIED
    if _TRIED:
        return _ENSEMBLE
    _TRIED = True
    try:
        if (MODELS_DIR / "sk.joblib").exists():
            from .anomaly import AnomalyEnsemble
            _ENSEMBLE = AnomalyEnsemble.load(str(MODELS_DIR))
    except Exception:
        _ENSEMBLE = None
    return _ENSEMBLE


def score_activity(activity: dict) -> dict | None:
    """Return the behavioral-anomaly signal for one source's activity, or None if the
    model is unavailable. Never raises: the agent treats this as optional evidence."""
    ens = _ensemble()
    if ens is None:
        return None
    try:
        x = build_features(activity)
        s = ens.score([x])
        pct = float(s["ensemble"][0])
        iso = float(s["iso_pct"][0])
        ae = s["ae_pct"][0]
        drivers = [d for d in ens.explain(x, k=3) if d["contribution"] > 0]
        models = {"isolation_forest": round(iso, 3)}
        if ae == ae:  # not NaN
            models["autoencoder"] = round(float(ae), 3)
        model_label = "ensemble of Isolation Forest + autoencoder" if "autoencoder" in models else "Isolation Forest"
        label = "anomalous" if pct >= THRESHOLD else "normal"
        return {
            "percentile": round(pct, 3),
            "label": label,
            "threshold": THRESHOLD,
            "models": models,
            "top_drivers": drivers,
            "note": (f"Behavioral model: {pct:.0%}-percentile {label} vs this environment's learned "
                     f"normal ({model_label})"),
        }
    except Exception:
        return None


def log_activity(activity: dict) -> None:
    """Append the observed feature vector so the model can later be retrained on real
    traffic (see ml/train.py). Best-effort; failures are swallowed."""
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        row = dict(zip(FEATURE_NAMES, build_features(activity)))
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except Exception:
        pass
