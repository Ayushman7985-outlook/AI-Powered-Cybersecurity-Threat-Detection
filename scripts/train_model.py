"""Train and evaluate the UNSW-NB15 classifier from the project root."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.threat_detection.data.loader import DEFAULT_TEST_PATH, DEFAULT_TRAIN_PATH
from src.threat_detection.ml.train import train_and_evaluate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, default=DEFAULT_TRAIN_PATH)
    parser.add_argument("--test", type=Path, default=DEFAULT_TEST_PATH)
    parser.add_argument("--estimators", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    try:
        train_and_evaluate(
            train_path=args.train,
            test_path=args.test,
            n_estimators=args.estimators,
            random_state=args.seed,
        )
    except Exception as exc:
        print(f"Training did not complete: {type(exc).__name__}: {exc}", file=sys.stderr)
        if isinstance(exc, ImportError) and "Application Control policy" in str(exc):
            print(
                "Windows blocked a compiled scientific-package component. "
                "No security control was changed and no model/metrics were created.",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
