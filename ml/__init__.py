"""Behavioral anomaly layer (UEBA) for CerberusAI.

An OPTIONAL, explainable machine-learning signal that complements the deterministic
checks (z-score baselining, topology drift). It learns each environment's normal
multivariate behavior and scores new activity, feeding an anomaly score plus the
features that drove it into the agent's investigation. It never makes the verdict on
its own; it is one more piece of evidence the agent weighs.

Two unsupervised models form an ensemble: an Isolation Forest (scikit-learn) and a
small autoencoder (PyTorch, optional). If the ML dependencies are not installed, the
rest of CerberusAI runs unchanged.
"""

from .features import FEATURE_NAMES, build_features

__all__ = ["FEATURE_NAMES", "build_features"]
