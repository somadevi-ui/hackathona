# AI-Based Cyber Threat Detection & Automated Incident Response

A working end-to-end demo: a Random Forest model detects network intrusions
(NSL-KDD dataset), and a rule-based response engine decides an action
(allow / flag for review / auto-contain) for every event in a simulated
real-time feed. A Streamlit dashboard shows it all live, SOC-style.

## Project structure

```
cyber_ai_project/
├── data/
│   ├── KDDTrain.txt          # NSL-KDD training set
│   └── KDDTest.txt           # NSL-KDD test set
├── columns.py                # column names + attack-category mapping
├── preprocess.py             # encoding, scaling, label prep
├── train_model.py            # trains RandomForest, saves model + metrics + charts
├── response_engine.py        # decision logic / playbooks (the "SOAR" layer)
├── simulate_stream.py        # replays test events as a live feed through model + response engine
├── dashboard.py              # Streamlit live dashboard
├── artifacts/                # generated: model, scaler, metrics, charts, incident log
└── requirements.txt
```

## Quick start

```bash
pip install -r requirements.txt

# 1. Train the model (run once) — saves model + charts to artifacts/
python train_model.py

# 2. Simulate a live threat feed (run this whenever you want new events)

python simulate_stream.py --events 500 --delay 0.2
# 3. Launch the live dashboard (run in a separate terminal, keep it open)
streamlit run dashboard.py
```

Open the local URL Streamlit prints (usually http://localhost:8501).
Re-run `simulate_stream.py` in another terminal any time to feed new
events into the dashboard — click "🔄 Refresh now" or wait for the
2-second cache to expire.

## How it works

1. **Detection** — `train_model.py` trains a `RandomForestClassifier`
   (balanced class weights) on NSL-KDD, predicting `normal` vs `attack`
   with a probability score.
2. **Simulated live feed** — `simulate_stream.py` shuffles the labeled
   test set and replays it row-by-row, as if events were arriving from
   a live sensor.
3. **Automated response** — `response_engine.py` maps prediction +
   confidence + attack category to a tiered action:
   - **High confidence attack** → automatic containment playbook
     (e.g. `AUTO_RATE_LIMIT_AND_BLOCK_SOURCE_IP` for DoS,
     `AUTO_ISOLATE_HOST_AND_KILL_PROCESS` for privilege escalation)
   - **Medium confidence** → `FLAG_FOR_ANALYST_REVIEW`
   - **Low confidence** → logged only, no action
   - **Normal traffic** → `ALLOW`
4. **Dashboard** — `dashboard.py` reads the generated incident log and
   metrics and renders live charts and a scrolling alert feed.

All response "actions" are **simulated and logged** (printed / written
to `artifacts/incident_log.jsonl`) — nothing here touches a real
firewall, host, or account. That's intentional: this demonstrates the
decision logic and pipeline, which is the safe and correct way to
prototype this kind of system before any real integration.

## Model performance (on held-out NSL-KDD test set)

Numbers land in `artifacts/metrics.json` after training; typically:

- **Precision ~0.95+** on the attack class (few false alarms)
- **Recall ~0.60-0.65** — NSL-KDD's test set intentionally includes
  attack types not present in training, to test generalization to
  novel/zero-day-style attacks. This is a known, well-documented
  property of the dataset, not a bug — and it's a good talking point:
  it shows the model catches most known attack patterns but, like any
  supervised classifier, is weaker against truly unseen attack types
  (which is exactly why real systems pair this with anomaly detection
  and human review).

See `artifacts/confusion_matrix.png` and `artifacts/feature_importance.png`
for visual breakdowns.

## Extending this

- Swap in `IsolationForest` or an autoencoder for unsupervised anomaly
  detection to catch novel attacks the classifier misses.
- Replace the shuffled-CSV "live feed" with a real packet capture
  (e.g. `scapy` + live feature extraction) for a true real-time system.
- Replace simulated actions in `response_engine.py` with real API calls
  (firewall API, IAM API) once you have a sandboxed test environment —
  never point automated containment actions at production systems
  without a human-in-the-loop safety net and a rollback plan.
