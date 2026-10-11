"""Validate official dataset files and write a factual summary and figures."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.threat_detection.data.loader import DEFAULT_TEST_PATH, DEFAULT_TRAIN_PATH, describe_frame, load_official_split
from src.threat_detection.visualization import save_dataset_figures


def main() -> int:
    split = load_official_split(DEFAULT_TRAIN_PATH, DEFAULT_TEST_PATH)
    report = {
        "training": describe_frame(split.train_frame, str(DEFAULT_TRAIN_PATH.relative_to(ROOT))),
        "testing": describe_frame(split.test_frame, str(DEFAULT_TEST_PATH.relative_to(ROOT))),
        "input_feature_count": int(split.X_train.shape[1]),
        "excluded_from_features": ["id", "attack_cat", "label"],
        "official_split_preserved": True,
    }
    print(json.dumps(report, indent=2))
    report_path = ROOT / "outputs" / "reports" / "dataset_validation.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    try:
        figures = save_dataset_figures(split.train_frame, ROOT / "outputs" / "figures")
        print("Generated figures:", ", ".join(str(path.relative_to(ROOT)) for path in figures))
    except Exception as exc:
        print(f"Dataset plots unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
    print(f"Saved report: {report_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())