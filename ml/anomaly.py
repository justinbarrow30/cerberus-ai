"""The anomaly ensemble: Isolation Forest + autoencoder.

Both are unsupervised. We fit them on normal behavior, then turn each model's raw
anomaly score into a PERCENTILE against the normal training distribution, so the two
very different scores become comparable (0..1) and the ensemble is just their mean.
A score near 1 means "more anomalous than almost all normal behavior ever seen."

Explainability: feature contributions by baseline substitution. For a given sample we
neutralize one feature at a time (set it to the normal median) and see how far the
anomaly score drops; the features whose removal drops it most are the ones that drove
the alarm. This works identically for both models and needs no extra dependency.

The autoencoder is optional. Without PyTorch, the ensemble is the Isolation Forest
alone and everything else behaves the same.
"""

from __future__ import annotations

import os

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

from .features import FEATURE_NAMES

# Count-like features are heavy-tailed; log1p compresses them so one huge value (a
# short-window rate spike, a brute-force burst) can't swamp the scale, and moderate
# counts are not over-flagged. Ratios and flags are already bounded, so left as-is.
_LOG_IDX = [0, 1, 2, 3, 5]  # failed_auths, successful_auths, distinct_targets, distinct_rules, events_per_min


def _transform(X) -> np.ndarray:
    X = np.asarray(X, float)
    if X.ndim == 1:
        X = X.reshape(1, -1)
    X = X.copy()
    X[:, _LOG_IDX] = np.log1p(np.clip(X[:, _LOG_IDX], 0, None))
    return X


def _torch():
    try:
        import torch  # noqa: F401
        return __import__("torch")
    except Exception:
        return None


def _build_ae(d: int):
    """A small undercomplete autoencoder: d -> 6 -> 3 -> 6 -> d."""
    t = _torch()
    import torch.nn as nn
    return nn.Sequential(
        nn.Linear(d, 6), nn.ReLU(),
        nn.Linear(6, 3), nn.ReLU(),
        nn.Linear(3, 6), nn.ReLU(),
        nn.Linear(6, d),
    )


def _train_ae(Z: np.ndarray, epochs: int = 200):
    t = _torch()
    import torch.nn as nn
    t.manual_seed(0)   # reproducible training so published metrics are stable
    model = _build_ae(Z.shape[1])
    X = t.tensor(Z, dtype=t.float32)
    opt = t.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = nn.MSELoss()
    model.train()
    for _ in range(epochs):
        opt.zero_grad()
        loss = loss_fn(model(X), X)
        loss.backward()
        opt.step()
    model.eval()
    return model


def _ae_error(model, Z: np.ndarray) -> np.ndarray:
    t = _torch()
    with t.no_grad():
        X = t.tensor(Z, dtype=t.float32)
        return ((model(X) - X) ** 2).mean(dim=1).cpu().numpy()


class AnomalyEnsemble:
    def __init__(self):
        self.scaler: StandardScaler | None = None
        self.iso: IsolationForest | None = None
        self.ae = None
        self.iso_norm: np.ndarray | None = None   # sorted normal-training anomaly scores
        self.ae_norm: np.ndarray | None = None
        self.baseline: np.ndarray | None = None    # median scaled vector, for explanations
        # mean/std of raw scores on normal, so explanations use a continuous (non-saturating) score
        self.iso_mu = self.iso_sd = self.ae_mu = self.ae_sd = None
        self.feature_names = FEATURE_NAMES

    # --- training --------------------------------------------------------------
    def fit(self, Xn: np.ndarray, use_ae: bool = True, epochs: int = 200) -> "AnomalyEnsemble":
        Xt = _transform(Xn)
        self.scaler = StandardScaler().fit(Xt)
        Z = self.scaler.transform(Xt)
        self.baseline = np.median(Z, axis=0)
        self.iso = IsolationForest(n_estimators=200, contamination="auto", random_state=0).fit(Z)
        iso_raw = -self.iso.score_samples(Z)
        self.iso_norm = np.sort(iso_raw)
        self.iso_mu, self.iso_sd = float(iso_raw.mean()), float(iso_raw.std() + 1e-9)
        if use_ae and _torch() is not None:
            self.ae = _train_ae(Z, epochs)
            ae_raw = _ae_error(self.ae, Z)
            self.ae_norm = np.sort(ae_raw)
            self.ae_mu, self.ae_sd = float(ae_raw.mean()), float(ae_raw.std() + 1e-9)
        return self

    # --- scoring ---------------------------------------------------------------
    @staticmethod
    def _pct(ref_sorted: np.ndarray, vals: np.ndarray) -> np.ndarray:
        return np.searchsorted(ref_sorted, vals, side="right") / len(ref_sorted)

    def _iso_pct(self, Z):
        return self._pct(self.iso_norm, -self.iso.score_samples(Z))

    def _ae_pct(self, Z):
        return self._pct(self.ae_norm, _ae_error(self.ae, Z))

    def _ensemble_scaled(self, Z: np.ndarray) -> np.ndarray:
        iso = self._iso_pct(Z)
        if self.ae is not None:
            return (iso + self._ae_pct(Z)) / 2.0
        return iso

    def _raw_scaled(self, Z: np.ndarray) -> np.ndarray:
        """Continuous (standardized) anomaly score. Unlike the percentile it does not
        saturate at 1.0, so it is what feature attribution differences are measured on."""
        iso_z = (-self.iso.score_samples(Z) - self.iso_mu) / self.iso_sd
        if self.ae is not None:
            ae_z = (_ae_error(self.ae, Z) - self.ae_mu) / self.ae_sd
            return (iso_z + ae_z) / 2.0
        return iso_z

    def score(self, X: np.ndarray) -> dict:
        """Per-sample percentiles for each model and the ensemble (0..1)."""
        Z = self.scaler.transform(_transform(np.atleast_2d(X)))
        iso = self._iso_pct(Z)
        if self.ae is not None:
            ae = self._ae_pct(Z)
            ens = (iso + ae) / 2.0
        else:
            ae = np.full_like(iso, np.nan)
            ens = iso
        return {"iso_pct": iso, "ae_pct": ae, "ensemble": ens}

    def anomaly_percentile(self, feat_vector) -> float:
        return float(self.score(np.asarray(feat_vector, float))["ensemble"][0])

    # --- explainability --------------------------------------------------------
    def explain(self, feat_vector, k: int = 3) -> list[dict]:
        x = np.asarray(feat_vector, float).reshape(1, -1)
        Zx = self.scaler.transform(_transform(x))[0]
        base = self._raw_scaled(Zx.reshape(1, -1))[0]
        out = []
        for i in range(len(FEATURE_NAMES)):
            Zc = Zx.copy()
            Zc[i] = self.baseline[i]
            drop = base - self._raw_scaled(Zc.reshape(1, -1))[0]
            out.append({"feature": FEATURE_NAMES[i], "contribution": round(float(drop), 4),
                        "value": round(float(x[0, i]), 3)})
        out.sort(key=lambda d: d["contribution"], reverse=True)
        return out[:k]

    # --- persistence -----------------------------------------------------------
    def save(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)
        joblib.dump({"scaler": self.scaler, "iso": self.iso}, os.path.join(path, "sk.joblib"))
        np.savez(os.path.join(path, "norm.npz"), iso_norm=self.iso_norm,
                 ae_norm=(self.ae_norm if self.ae_norm is not None else np.array([])),
                 baseline=self.baseline,
                 stats=np.array([self.iso_mu, self.iso_sd,
                                 self.ae_mu if self.ae_mu is not None else 0.0,
                                 self.ae_sd if self.ae_sd is not None else 1.0]))
        if self.ae is not None:
            _torch().save(self.ae.state_dict(), os.path.join(path, "ae.pt"))

    @classmethod
    def load(cls, path: str) -> "AnomalyEnsemble":
        e = cls()
        sk = joblib.load(os.path.join(path, "sk.joblib"))
        e.scaler, e.iso = sk["scaler"], sk["iso"]
        z = np.load(os.path.join(path, "norm.npz"))
        e.iso_norm, e.baseline = z["iso_norm"], z["baseline"]
        ae_norm = z["ae_norm"]
        e.ae_norm = ae_norm if ae_norm.size else None
        st = z["stats"]
        e.iso_mu, e.iso_sd, e.ae_mu, e.ae_sd = float(st[0]), float(st[1]), float(st[2]), float(st[3])
        ae_path = os.path.join(path, "ae.pt")
        t = _torch()
        if t is not None and e.ae_norm is not None and os.path.exists(ae_path):
            e.ae = _build_ae(len(FEATURE_NAMES))
            e.ae.load_state_dict(t.load(ae_path))
            e.ae.eval()
        return e
