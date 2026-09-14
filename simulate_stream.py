"""
Simulates a live network event feed by replaying the labeled test set
row-by-row through the trained model and the automated response engine.
Writes a structured incident log (JSONL) and prints a running summary --
this is the core "detect + respond in real time" demo.
"""

import json
import time
import argparse
import pandas as pd
import joblib

from response_engine import decide_action

ARTIFACT_DIR = "artifacts"
LOG_PATH = f"{ARTIFACT_DIR}/incident_log.jsonl"


def load_artifacts():
    model = joblib.load(f"{ARTIFACT_DIR}/model.joblib")
    scaler = joblib.load(f"{ARTIFACT_DIR}/scaler.joblib")
    encoders = joblib.load(f"{ARTIFACT_DIR}/encoders.joblib")
    feature_cols = joblib.load(f"{ARTIFACT_DIR}/feature_cols.joblib")
    return model, scaler, encoders, feature_cols


def main(num_events, delay, seed, malicious_rate):
    model, scaler, encoders, feature_cols = load_artifacts()
    df = pd.read_csv(f"{ARTIFACT_DIR}/test_with_predictions.csv")

    # Build a controlled demo mix, then shuffle it so malicious events are interleaved.
    if not 0 <= malicious_rate <= 1:
        raise ValueError("malicious_rate must be between 0 and 1")
    event_count = num_events or len(df)
    malicious_count = round(event_count * malicious_rate)
    benign_count = event_count - malicious_count
    malicious_rows = df[df["predicted_label"] == 1]
    benign_rows = df[df["predicted_label"] == 0]
    if malicious_count > len(malicious_rows) or benign_count > len(benign_rows):
        raise ValueError(
            f"Not enough source events for a {malicious_rate:.0%} malicious mix "
            f"of {event_count} events"
        )
    malicious_sample = malicious_rows.sample(n=malicious_count, random_state=seed)
    benign_sample = benign_rows.sample(n=benign_count, random_state=seed + 1)
    df = pd.concat([malicious_sample, benign_sample]).sample(frac=1, random_state=seed).reset_index(drop=True)

    counts = {"ALLOW": 0, "FLAG_FOR_ANALYST_REVIEW": 0, "LOG_ONLY_LOW_CONFIDENCE": 0}
    auto_actions = 0

    with open(LOG_PATH, "w") as log_file:
        for i, row in df.iterrows():
            prediction = int(row["predicted_label"])
            confidence = float(row["attack_confidence"])
            category = row["attack_category"]

            src_info = {
                "event_id": int(i),
                "protocol": row["protocol_type"],
                "service": row["service"],
                "flag": row["flag"],
                "src_bytes": int(row["src_bytes"]),
                "dst_bytes": int(row["dst_bytes"]),
                "true_label": row["label"],
            }

            result = decide_action(prediction, confidence, category, src_info)
            log_file.write(json.dumps(result) + "\n")
            log_file.flush()

            action = result["action"]
            if action in counts:
                counts[action] += 1
            elif action.startswith("AUTO_"):
                auto_actions += 1

            tag = "🟢" if action == "ALLOW" else ("🟠" if "REVIEW" in action or "LOW" in action else "🔴")
            print(f"{tag} event={i:<6} verdict={result['verdict']:<14} "
                  f"conf={result['confidence']:<6} action={action}")

            if delay:
                time.sleep(delay)

    print("\n--- Run summary ---")
    print(f"Total events processed : {len(df)}")
    print(f"Allowed (benign)        : {counts['ALLOW']}")
    print(f"Auto-response triggered : {auto_actions}")
    print(f"Flagged for analyst     : {counts['FLAG_FOR_ANALYST_REVIEW']}")
    print(f"Low-confidence logged   : {counts['LOG_ONLY_LOW_CONFIDENCE']}")
    print(f"Full incident log       : {LOG_PATH}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate a live threat-detection feed.")
    parser.add_argument("--events", type=int, default=200, help="Number of events to simulate (0 = all)")
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds to sleep between events (for a live-looking demo)")
    parser.add_argument("--seed", type=int, default=7, help="Shuffle seed")
    parser.add_argument("--malicious-rate", type=float, default=0.60, help="Target share of model-detected malicious events (default: 0.60)")
    args = parser.parse_args()
    main(args.events, args.delay, args.seed, args.malicious_rate)
