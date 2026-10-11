"""Run safe, offline predictions on dataset and explicitly synthetic samples."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.threat_detection.data.loader import load_official_split
from src.threat_detection.database.repository import DetectionRepository
from src.threat_detection.ml.predict import DEFAULT_MODEL_PATH, PredictionEngine
from src.threat_detection.simulation.demo import run_simulation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "detections.sqlite3")
    args = parser.parse_args()
    try:
        split = load_official_split()
        engine = PredictionEngine.from_path(args.model)
        results = run_simulation(
            engine,
            split.train_frame,
            split.test_frame,
            repository=DetectionRepository(args.database),
        )
    except Exception as exc:
        print(f"Simulation unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        print("Train a verified model first; no placeholder predictions are produced.", file=sys.stderr)
        return 1
    print(json.dumps(results, indent=2))
    print("Saved simulation report: outputs/reports/simulation_results.json")
    print(f"Saved event history to: {args.database}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())