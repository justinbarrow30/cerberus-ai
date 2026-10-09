# Behavioral anomaly layer (optional ML)

An explainable, UEBA-style machine-learning signal that complements CerberusAI's
deterministic checks (per-host z-score baselining, topology drift). It learns an
environment's normal multivariate behavior and scores new activity, feeding an anomaly
score plus the features that drove it into the agent's investigation.

It is **one signal the agent weighs, never the judge.** The deterministic core still
produces the grounded verdict; this layer adds "is this combination of behaviors weird
compared to everything we've seen?", which single-metric statistics can miss. The whole
layer is optional: without the ML dependencies installed, CerberusAI runs unchanged.

## Why ML here (and why it stays explainable)

Per-host statistics catch single-metric anomalies ("failed logins far above this host's
baseline"). They miss unusual *combinations* across many features at once. That is the
textbook case for anomaly-detection ML. To keep the auditability that makes CerberusAI
easy to approve, every score comes with **feature attributions**: the features whose
removal most reduces the anomaly score, so a verdict is never a mystery number.

## The models (an ensemble)

Two unsupervised models, trained only on normal behavior:

- **Isolation Forest** (scikit-learn): isolates outliers with random partitioning.
- **Autoencoder** (PyTorch, optional): a small `8 -> 6 -> 3 -> 6 -> 8` network; high
  reconstruction error means "unlike normal". If PyTorch is absent, the ensemble is the
  Isolation Forest alone.

Each model's raw score is converted to a **percentile against the normal training
distribution**, which makes the two comparable; the ensemble is their mean. A score of
0.98 means "more anomalous than 98% of normal behavior ever seen."

## Features (per source/entity)

`failed_auths`, `successful_auths`, `distinct_targets` (fan-out), `distinct_rules`,
`failed_ratio`, `events_per_min`, `off_hours`, `new_target_ratio`. Count features are
`log1p`-transformed so one huge value cannot swamp the scale. (See `features.py`.)

## Evaluation

### 1. Synthetic benchmark (method check, not performance)

Trained unsupervised on normal behavior, then scored on a held-out mix of normal +
synthetic attacks (brute force, lateral spread, off-hours stealth, blended). The
distributions deliberately overlap, so the task is non-trivial. Reproduce with
`python -m ml.evaluate`:

| Model | ROC-AUC | PR-AUC | Precision | Recall | F1 |
|-------|:------:|:-----:|:--------:|:-----:|:--:|
| Isolation Forest | 0.995 | 0.994 | 0.954 | 0.988 | 0.971 |
| Autoencoder | 0.988 | 0.989 | 0.956 | 0.912 | 0.933 |
| **Ensemble** | **0.996** | **0.997** | **0.988** | **0.958** | **0.973** |

<sub>Precision/recall at a 95th-percentile threshold. The ensemble beats either model
alone, which is the point of combining them.</sub>

![ROC curves](../docs/ml_roc.png)

**Be honest about what this is.** The attacks and the normal traffic are both
generated here, so these numbers prove the *method and the pipeline work*, not that the
models perform well on real traffic. A high score on your own synthetic data is not
evidence of real-world performance.

### 2. Real labeled data: LANL auth + red team

`ml/eval_lanl.py` runs the same ensemble against the Los Alamos "Comprehensive
Multi-Source Cyber-Security Events" dataset: real enterprise authentication logs
(`auth.txt`) with real red-team compromise events (`redteam.txt`). It buckets auth into
per-source-computer time windows, aggregates the same features, labels a window
malicious if it contains a red-team event, trains unsupervised on benign windows, and
scores held-out benign + malicious windows.

```bash
# get the data (accept the license): https://csr.lanl.gov/data/cyber1/
python -m ml.eval_lanl --auth auth.txt.gz --redteam redteam.txt
python -m ml.eval_lanl --auth auth.txt.gz --redteam redteam.txt --limit 20000000  # a slice
```

Status: the pipeline is implemented and verified end-to-end on a small LANL-format
sample. Real numbers require the dataset (it is multi-GB and license-gated, so it is not
vendored here). This is the evaluation that actually measures the model; the synthetic
one above is only a sanity check.

## Running it

```bash
pip install -r requirements-ml.txt   # numpy, scikit-learn, joblib, matplotlib, torch (optional)

python -m ml.evaluate                # train + measure on synthetic data, save the ROC plot
python -m ml.train --bootstrap       # cold-start a shippable model on synthetic normal
python -m ml.train                   # later: retrain on the real behavior CerberusAI logged
```

The agent calls the trained model automatically (see `runtime.py`, wired into
`agent.query_siem`) and appends a signal like *"Behavioral model: 100%-percentile
anomalous ... driven by a never-before-seen destination"* to the evidence.

## Honest notes

- The shipped model is a **cold-start** trained on synthetic normal behavior, so it
  flags environment-independent extremes out of the box. Retrain on your own logged
  traffic (`python -m ml.train`) for per-environment accuracy; CerberusAI logs the
  feature vectors it observes to `ml/behavior_log.jsonl` for exactly this.
- The model learns a **global** notion of normal; the deterministic layer knows each
  host's **own** baseline. They disagree sometimes, and that is by design: the agent
  reconciles both, so a host that looks odd globally but is normal for itself is still
  auto-closed.
