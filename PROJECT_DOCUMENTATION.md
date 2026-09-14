# Sentinel Project Documentation

## 1. Project Overview

Sentinel is a cybersecurity demonstration platform. It detects network attacks
with a Random Forest model and recommends simulated response actions through a
Streamlit security operations dashboard.

The project is designed to show this workflow:

```text
Network event -> ML detection -> Confidence score -> Response decision -> SOC dashboard
```

All response actions are simulated. The project does not connect to real
firewalls, hosts, accounts, or networks.

## 2. Main Components

- `train_model.py`: trains the Random Forest classifier.
- `preprocess.py`: prepares and transforms NSL-KDD data.
- `columns.py`: defines dataset columns and attack categories.
- `simulate_stream.py`: replays test events into the incident log.
- `response_engine.py`: selects an action from the prediction and confidence.
- `dashboard.py`: displays the live SOC dashboard.
- `artifacts/`: stores the trained model, metrics, charts, and event log.

## 3. Requirements

Install the Python packages with:

```powershell
pip install -r requirements.txt
```

The project uses Python, pandas, scikit-learn, Plotly, joblib, and Streamlit.

## 4. Running the Project

### Train the model

Run this once when the model artifacts do not exist:

```powershell
python train_model.py
```

### Start the event feed

Run this in a separate terminal:

```powershell
python simulate_stream.py --events 300 --delay 0.2
```

This replays 300 events with a 0.2 second delay and writes the results to:

```text
artifacts/incident_log.jsonl
```

### Start the dashboard

Run this in another terminal:

```powershell
streamlit run dashboard.py
```

If the global Python commands are unavailable, use the workspace environment:

```powershell
.venv\Scripts\python.exe simulate_stream.py --events 300 --delay 0.2
.venv\Scripts\streamlit.exe run dashboard.py --server.port 8513
```

Open the local URL shown by Streamlit. In the current workspace it is:

```text
http://localhost:8513/
```

## 5. Dashboard Login

The dashboard opens with a local operator login screen.

The only accepted demo credentials are:

```text
Operator ID: Aniketdubey
Passphrase: 123456789
```

Use **Sign out** in the dashboard header to return to the login screen. This
is a lightweight demo gate, not production authentication. A production
deployment should use an identity provider, secure session management, and
server-side authorization.

## 6. Dashboard Areas

### Overview

Shows the main operational metrics:

- Events processed
- Threats detected
- High-risk incidents
- Automated actions
- Blocked events
- Threat activity chart
- Current threat level
- Business impact metrics

### Incident Queue

Shows the latest high-signal incidents and their response state.

### Threat Map

Displays animated source, attack-category, and target nodes. The path is a
visual representation of the selected incident and does not send network data.

### Response Playbooks

Shows available simulated actions such as source blocking, host isolation, and
analyst review.

The `Run playbook` button displays the response workflow:

```text
Validate confidence -> Block source -> Isolate host -> Record evidence -> Verify containment
```

### Model Health

Shows model quality metrics from `artifacts/metrics.json`:

- Accuracy
- Precision
- Recall
- F1 score
- Confusion matrix

### Explainable AI

The selected incident displays network fields used to explain the detection,
including:

- `src_bytes`
- `protocol`
- `dst_host_count`
- `service`
- `flag`

### Live Log Stream

The complete incident log is shown newest first. The log panel refreshes every
two seconds and displays:

- Timestamp
- Verdict
- Confidence
- Severity
- Recommended action
- Event details

The dashboard also supports filtering by severity, verdict, and action, plus
CSV export of the filtered feed.

## 7. Response Logic

The response engine uses confidence thresholds:

- Normal traffic: `ALLOW`
- High-confidence attack: automatic simulated containment
- Medium-confidence attack: `FLAG_FOR_ANALYST_REVIEW`
- Low-confidence attack: `LOG_ONLY_LOW_CONFIDENCE`

Example simulated actions include:

- Rate limit and block a DoS source
- Temporarily block a scanning source
- Disable an account and require MFA reset
- Isolate a host pending review

## 8. Generated Artifacts

Important files in `artifacts/` include:

- `model.joblib`: trained classifier.
- `scaler.joblib`: feature scaler.
- `encoders.joblib`: categorical encoders.
- `feature_cols.joblib`: model feature names.
- `metrics.json`: evaluation metrics.
- `incident_log.jsonl`: live event log.
- `confusion_matrix.png`: model evaluation chart.
- `feature_importance.png`: feature importance chart.

## 9. Safety Notes

This is a controlled demonstration. The response engine only writes decisions
to the local incident log. It does not perform real containment.

Before connecting a similar system to production infrastructure, add:

- Human approval for high-impact actions.
- Authentication and authorization.
- Audit logging and rollback support.
- A sandbox environment.
- Monitoring for false positives and model drift.
