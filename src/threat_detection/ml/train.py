"""Train and evaluate a leakage-safe Random Forest pipeline."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..data.loader import DEFAULT_TEST_PATH, DEFAULT_TRAIN_PATH, PROJECT_ROOT, load_official_split


def build_pipeline(X_train: Any, n_estimators: int = 100, random_state: int = 42, n_jobs: int = -1) -> Any:
    """Create training-only imputation/encoding and a seeded Random Forest.

    Scaling is intentionally omitted because decision-tree splits do not depend
    on feature units. Unseen categories are ignored by the fitted encoder.
    """
    if n_estimators < 1:
        raise ValueError("n_estimators must be at least 1.")
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder

    categorical = X_train.select_dtypes(include=["object", "category", "bool"]).columns.tolist()
    numeric = [column for column in X_train.columns if column not in categorical]
    transformers = []
    if numeric:
        transformers.append(("numeric", Pipeline([("imputer", SimpleImputer(strategy="median"))]), numeric))
    if categorical:
        transformers.append(("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=10)),
        ]), categorical))
    return Pipeline([
        ("preprocessing", ColumnTransformer(transformers=transformers, remainder="drop")),
        ("classifier", RandomForestClassifier(
            n_estimators=n_estimators, class_weight="balanced",
            random_state=random_state, n_jobs=n_jobs,
        )),
    ])


def train_and_evaluate(
    train_path: str | Path = DEFAULT_TRAIN_PATH,
    test_path: str | Path = DEFAULT_TEST_PATH,
    model_path: str | Path = PROJECT_ROOT / "models" / "random_forest_pipeline.joblib",
    metrics_path: str | Path = PROJECT_ROOT / "outputs" / "metrics" / "evaluation.json",
    n_estimators: int = 100,
    random_state: int = 42,
) -> dict[str, Any]:
    """Fit on the official training data and evaluate once on the official test."""
    split = load_official_split(train_path, test_path)
    numeric_count = len(split.X_train.select_dtypes(include=["number"]).columns)
    categorical_count = split.X_train.shape[1] - numeric_count
    print(f"Official training records: {len(split.X_train):,}")
    print(f"Official testing records:  {len(split.X_test):,}")
    print(f"Input features: {split.X_train.shape[1]} (id/label/attack_cat excluded)")
    print(f"Numeric: {numeric_count}; categorical: {categorical_count}")
    print("Training Random Forest; preprocessing is fitted on training data only...")
    model = build_pipeline(split.X_train, n_estimators, random_state)
    started = time.perf_counter()
    model.fit(split.X_train, split.y_train)
    elapsed = time.perf_counter() - started
    predictions = model.predict(split.X_test)

    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
    import joblib

    matrix = confusion_matrix(split.y_test, predictions, labels=[0, 1])
    metrics: dict[str, Any] = {
        "model": "RandomForestClassifier", "dataset": "UNSW-NB15",
        "positive_class": 1, "positive_class_name": "Attack",
        "training_rows": int(len(split.X_train)), "testing_rows": int(len(split.X_test)),
        "input_feature_count": int(split.X_train.shape[1]),
        "excluded_columns": ["id", "attack_cat", "label"],
        "numeric_feature_count": numeric_count, "categorical_feature_count": categorical_count,
        "n_estimators": n_estimators, "random_state": random_state,
        "training_seconds": round(elapsed, 3),
        "accuracy": float(accuracy_score(split.y_test, predictions)),
        "precision": float(precision_score(split.y_test, predictions, zero_division=0)),
        "recall": float(recall_score(split.y_test, predictions, zero_division=0)),
        "f1_score": float(f1_score(split.y_test, predictions, zero_division=0)),
        "confusion_matrix_labels": ["Normal", "Attack"],
        "confusion_matrix": matrix.astype(int).tolist(),
        "classification_report": classification_report(
            split.y_test, predictions, labels=[0, 1], target_names=["Normal", "Attack"],
            output_dict=True, zero_division=0,
        ),
    }
    model_destination, metrics_destination = Path(model_path), Path(metrics_path)
    model_destination.parent.mkdir(parents=True, exist_ok=True)
    metrics_destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_destination)
    metrics_destination.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    from ..visualization import save_confusion_matrix
    figure_path = PROJECT_ROOT / "outputs" / "figures" / "confusion_matrix.png"
    save_confusion_matrix(metrics["confusion_matrix"], figure_path)
    print("\nHeld-out test results (positive class: Attack=1)")
    for name in ("accuracy", "precision", "recall", "f1_score"):
        print(f"{name.replace('_', ' ').title():10s}: {metrics[name]:.4f}")
    print(f"Confusion matrix [Normal, Attack]: {metrics['confusion_matrix']}")
    print(f"Training time: {elapsed:.2f} seconds")
    print(f"Saved model: {model_destination}\nSaved metrics: {metrics_destination}\nSaved confusion matrix: {figure_path}")
    return metrics
