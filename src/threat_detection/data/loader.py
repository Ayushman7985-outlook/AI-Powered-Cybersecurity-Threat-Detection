"""Dataset loading and schema checks for the official UNSW-NB15 split."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_TRAIN_PATH = PROJECT_ROOT / "data" / "raw" / "UNSW_NB15_training-set.csv"
DEFAULT_TEST_PATH = PROJECT_ROOT / "data" / "raw" / "UNSW_NB15_testing-set.csv"
TARGET_COLUMN = "label"
NON_FEATURE_COLUMNS = {"label", "attack_cat", "id"}


@dataclass(frozen=True)
class DatasetSplit:
    """The official train/test frames with leakage-safe feature matrices."""

    train_frame: pd.DataFrame
    test_frame: pd.DataFrame
    X_train: pd.DataFrame
    y_train: pd.Series
    X_test: pd.DataFrame
    y_test: pd.Series


def load_csv(path: str | Path) -> pd.DataFrame:
    """Read a CSV and fail with a useful message for missing or invalid files."""
    csv_path = Path(path).expanduser()
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset CSV does not exist: {csv_path}")
    try:
        frame = pd.read_csv(csv_path, low_memory=False)
    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not read dataset CSV {csv_path}: {exc}") from exc
    validate_frame(frame, source=str(csv_path))
    return frame


def validate_frame(frame: pd.DataFrame, source: str = "dataset") -> None:
    """Check target, columns, and binary label values before processing."""
    if frame.empty:
        raise ValueError(f"{source} contains no records.")
    if frame.columns.duplicated().any():
        duplicates = frame.columns[frame.columns.duplicated()].tolist()
        raise ValueError(f"{source} has duplicate column names: {duplicates}")
    if TARGET_COLUMN not in frame.columns:
        raise ValueError(f"{source} is missing required target column '{TARGET_COLUMN}'.")
    labels = pd.to_numeric(frame[TARGET_COLUMN], errors="coerce")
    if labels.isna().any() or not set(labels.unique()).issubset({0, 1}):
        raise ValueError(f"{source} target '{TARGET_COLUMN}' must contain only 0 and 1.")
    features = [column for column in frame.columns if column not in NON_FEATURE_COLUMNS]
    if not features:
        raise ValueError(f"{source} contains no usable input features.")


def load_official_split(
    train_path: str | Path = DEFAULT_TRAIN_PATH,
    test_path: str | Path = DEFAULT_TEST_PATH,
) -> DatasetSplit:
    """Load official files, preserve their split, and exclude target/ID leakage."""
    train_frame = load_csv(train_path)
    test_frame = load_csv(test_path)
    train_columns = set(train_frame.columns)
    test_columns = set(test_frame.columns)
    if train_columns != test_columns:
        only_train = sorted(train_columns - test_columns)
        only_test = sorted(test_columns - train_columns)
        raise ValueError(
            "Training and testing schemas differ; "
            f"only in train={only_train}, only in test={only_test}."
        )
    feature_columns = [
        column for column in train_frame.columns if column not in NON_FEATURE_COLUMNS
    ]
    X_train = train_frame.loc[:, feature_columns].copy()
    X_test = test_frame.loc[:, feature_columns].copy()
    y_train = pd.to_numeric(train_frame[TARGET_COLUMN], errors="raise").astype("int64")
    y_test = pd.to_numeric(test_frame[TARGET_COLUMN], errors="raise").astype("int64")
    return DatasetSplit(train_frame, test_frame, X_train, y_train, X_test, y_test)


def describe_frame(frame: pd.DataFrame, source: str = "dataset") -> dict[str, Any]:
    """Return a JSON-safe summary for logs and documentation."""
    return {
        "source": source,
        "rows": int(frame.shape[0]),
        "columns": int(frame.shape[1]),
        "column_names": frame.columns.tolist(),
        "data_types": {name: str(dtype) for name, dtype in frame.dtypes.items()},
        "missing_values": int(frame.isna().sum().sum()),
        "duplicate_rows": int(frame.duplicated().sum()),
        "label_distribution": {
            str(int(label)): int(count)
            for label, count in frame[TARGET_COLUMN].value_counts().sort_index().items()
        },
        "attack_category_distribution": (
            {
                str(category): int(count)
                for category, count in frame["attack_cat"].value_counts(dropna=False).items()
            }
            if "attack_cat" in frame.columns
            else None
        ),
    }