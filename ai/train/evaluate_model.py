"""Evaluate the saved SentinelAI model on a held-out stratified split."""

import os
import sys
import hashlib
from datetime import datetime

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score
)
from sklearn.model_selection import train_test_split

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ai.firewall.firewall_policy import get_block_threshold


DATASET_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "dataset",
    "processed",
    "sentinelai_training_data.csv"
)
MODEL_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "models",
    "sentinelai_model.joblib"
)

FEATURES = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "FIN Flag Count"
]
BLOCK_THRESHOLD = get_block_threshold()


def evaluate_saved_model(block_threshold=BLOCK_THRESHOLD):
    if not os.path.isfile(DATASET_FILE):
        raise FileNotFoundError(f"Evaluation dataset not found: {DATASET_FILE}")
    if not os.path.isfile(MODEL_FILE):
        raise FileNotFoundError(f"Saved model not found: {MODEL_FILE}")

    data = pd.read_csv(DATASET_FILE)
    missing = [feature for feature in FEATURES if feature not in data.columns]
    if missing:
        raise ValueError(f"Dataset is missing model features: {missing}")

    labels = (data["Label"] != "Benign").astype(int)
    _, X_test, _, y_test, _, test_labels = train_test_split(
        data[FEATURES],
        labels,
        data["Label"],
        test_size=0.2,
        random_state=42,
        stratify=labels
    )

    model = joblib.load(MODEL_FILE)
    predictions = model.predict(X_test)
    class_order = list(model.classes_)
    attack_index = class_order.index(1)
    attack_probabilities = model.predict_proba(X_test)[:, attack_index]

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    ).ravel()

    family_metrics = {}
    for family in sorted(test_labels[test_labels != "Benign"].unique()):
        family_mask = test_labels.to_numpy() == family
        family_count = int(family_mask.sum())
        family_detected = int(((predictions == 1) & family_mask).sum())
        family_metrics[str(family)] = {
            "total": family_count,
            "detected": family_detected,
            "recall": family_detected / max(family_count, 1)
        }

    accuracy = float(accuracy_score(y_test, predictions))
    precision = float(precision_score(y_test, predictions, zero_division=0))
    recall = float(recall_score(y_test, predictions, zero_division=0))
    f1 = float(f1_score(y_test, predictions, zero_division=0))
    false_positive_rate = fp / max(fp + tn, 1)
    missed_attack_rate = fn / max(fn + tp, 1)
    threshold_tradeoffs = []
    for threshold in sorted(set([block_threshold, 0.70, 0.80, 0.90, 0.95, 0.99])):
        block_decisions = (predictions == 1) & (attack_probabilities >= threshold)
        threshold_tradeoffs.append({
            "threshold": float(threshold),
            "false_blocks": int(((y_test.to_numpy() == 0) & block_decisions).sum()),
            "attacks_not_blocked": int(((y_test.to_numpy() == 1) & ~block_decisions).sum())
        })

    report = {
        "evaluated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "evaluation_method": "Saved model evaluated on a held-out 20% stratified split; no retraining performed.",
        "held_out_samples": int(len(y_test)),
        "class_counts": {
            "normal": int((y_test.to_numpy() == 0).sum()),
            "attack": int((y_test.to_numpy() == 1).sum())
        },
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_alarms": int(fp),
            "missed_attacks": int(fn),
            "false_positive_rate": float(false_positive_rate),
            "missed_attack_rate": float(missed_attack_rate),
            "true_normal": int(tn),
            "false_alarm_count": int(fp),
            "missed_attack_count": int(fn),
            "detected_attacks": int(tp)
        },
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "attack_family_recall": family_metrics,
        "block_threshold": float(block_threshold),
        "block_threshold_tradeoffs": threshold_tradeoffs,
        "model_sha256": _sha256_file(MODEL_FILE),
        "dataset_sha256": _sha256_file(DATASET_FILE)
    }
    return report


def main():
    report = evaluate_saved_model()
    metrics = report["metrics"]
    print("SENTINELAI SAVED-MODEL EVALUATION")
    print(f"Held-out samples: {report['held_out_samples']}")
    print(f"Accuracy: {metrics['accuracy']:.3f}")
    print(f"Precision: {metrics['precision']:.3f}")
    print(f"Recall: {metrics['recall']:.3f}")
    print(f"F1 score: {metrics['f1']:.3f}")
    print(f"False alarms (benign predicted attack): {metrics['false_alarms']}")
    print(f"Missed attacks (attack predicted normal): {metrics['missed_attacks']}")
    print(f"False-positive rate: {metrics['false_positive_rate']:.3%}")
    print(f"Missed-attack rate: {metrics['missed_attack_rate']:.3%}")
    print(f"\nConfusion matrix [NORMAL, ATTACK]:\n{report['confusion_matrix']}")
    print("\nAttack-family recall:")
    for family, values in report["attack_family_recall"].items():
        print(f"  {family}: {values['detected']}/{values['total']} ({values['recall']:.1%})")
    print("\nBlock-threshold trade-off (model prediction is ATTACK and risk meets threshold):")
    for item in report["block_threshold_tradeoffs"]:
        print(f"  {item['threshold']:.0%}: false blocks={item['false_blocks']}; attacks not blocked={item['attacks_not_blocked']}")
    print(f"\nConfigured automatic-block threshold: {report['block_threshold']:.0%}")
    print("\nThis evaluates the saved model without retraining or changing firewall rules.")


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
