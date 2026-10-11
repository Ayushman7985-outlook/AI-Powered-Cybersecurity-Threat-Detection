"""Safe model loading and schema-validated single/batch inference."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "random_forest_pipeline.joblib"


class ModelNotReadyError(RuntimeError):
    """Raised when no trained model artifact is available."""


class ModelLoadError(RuntimeError):
    """Raised when an existing model artifact cannot be loaded."""


class InvalidFeaturesError(ValueError):
    """Raised when an inference record does not match the model schema."""


class PredictionEngine:
    """Wrap a fitted sklearn pipeline; inference always uses its fitted transforms."""

    def __init__(self, model: Any):
        self.model = model
        feature_names = getattr(model, "feature_names_in_", None)
        if feature_names is None:
            raise ModelLoadError("Model artifact does not expose its fitted feature schema.")
        self.feature_names = [str(name) for name in feature_names]

    @classmethod
    def from_path(cls, model_path: str | Path = DEFAULT_MODEL_PATH) -> "PredictionEngine":
        path = Path(model_path).expanduser()
        if not path.is_file():
            raise ModelNotReadyError(
                "Trained model artifact is missing; run scripts/train_model.py "
                "in an authorized environment."
            )
        try:
            import joblib

            return cls(joblib.load(path))
        except ModelLoadError:
            raise
        except Exception as exc:
            raise ModelLoadError(
                f"Could not load the configured model artifact ({type(exc).__name__})."
            ) from exc

    def validate_features(self, features: dict[str, Any]) -> None:
        if not isinstance(features, dict):
            raise InvalidFeaturesError("features must be a JSON object.")
        expected, supplied = set(self.feature_names), set(features)
        missing, unexpected = sorted(expected - supplied), sorted(supplied - expected)
        if missing or unexpected:
            details = []
            if missing:
                details.append(f"missing features: {missing}")
            if unexpected:
                details.append(f"unexpected features: {unexpected}")
            raise InvalidFeaturesError("Invalid feature schema; " + "; ".join(details))
        for name, value in features.items():
            if value is None or isinstance(value, str):
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise InvalidFeaturesError(f"Feature '{name}' must be text, a number, or null.")
            try:
                is_finite = math.isfinite(float(value))
            except (OverflowError, ValueError):
                is_finite = False
            if not is_finite:
                raise InvalidFeaturesError(f"Feature '{name}' must be finite or null.")

    def predict_batch(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not records:
            raise InvalidFeaturesError("At least one record is required.")
        for record in records:
            self.validate_features(record)
        frame = pd.DataFrame(records, columns=self.feature_names)
        predictions = self.model.predict(frame)
        probabilities = self.model.predict_proba(frame) if hasattr(self.model, "predict_proba") else None
        classifier = getattr(self.model, "named_steps", {}).get("classifier")
        classes = list(getattr(classifier, "classes_", [0, 1]))
        results = []
        for index, raw_prediction in enumerate(predictions):
            prediction = int(raw_prediction)
            row_probabilities = probabilities[index] if probabilities is not None else None
            probability_by_class = (
                {int(label): float(score) for label, score in zip(classes, row_probabilities)}
                if row_probabilities is not None
                else {}
            )
            results.append(
                {
                    "predicted_label": prediction,
                    "prediction": "attack" if prediction == 1 else "normal",
                    "confidence": max(probability_by_class.values()) if probability_by_class else None,
                    "attack_probability": probability_by_class.get(1),
                    "probability_is_calibrated": False,
                }
            )
        return results

    def predict_one(self, features: dict[str, Any]) -> dict[str, Any]:
        return self.predict_batch([features])[0]