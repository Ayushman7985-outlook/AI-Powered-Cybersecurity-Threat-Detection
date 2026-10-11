"""Predict one real dataset row using an already trained local model."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.threat_detection.data.loader import load_official_split
from src.threat_detection.detection.alerts import create_alert
from src.threat_detection.ml.predict import DEFAULT_MODEL_PATH, PredictionEngine

DEFAULT_OUTPUT_PATH = ROOT / "outputs" / "reports" / "sample_prediction.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("train", "test"), default="test")
    parser.add_argument("--index", type=int, default=0, help="Zero-based row index in the selected split.")
    parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()
    try:
        split = load_official_split()
        features_frame = split.X_test if args.split == "test" else split.X_train
        labels = split.y_test if args.split == "test" else split.y_train
        if not 0 <= args.index < len(features_frame):
            raise IndexError(f"index must be between 0 and {len(features_frame) - 1}.")
        raw_record = features_frame.iloc[args.index].to_dict()
        features = {
            name: value.item() if hasattr(value, "item") else value
            for name, value in raw_record.items()
        }
        result = PredictionEngine.from_path(args.model).predict_one(features)
        report = {
            "source_type": "dataset",
            "split": args.split,
            "row_index": args.index,
            "dataset_label_for_comparison_only": int(labels.iloc[args.index]),
            **result,
            "alert": create_alert(result, "dataset"),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        print(f"Saved prediction report: {args.output}")
    except Exception as exc:
        print(f"Prediction unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        print("No placeholder prediction was generated.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())