"""FastAPI endpoints for model status, predictions, and minimal event history."""

from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
import json
import os
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..database.repository import DEFAULT_DATABASE_PATH, DetectionRepository
from ..data.loader import DEFAULT_TEST_PATH, DEFAULT_TRAIN_PATH, PROJECT_ROOT, describe_frame, load_official_split
from ..detection.alerts import create_alert
from ..ml.predict import DEFAULT_MODEL_PATH, InvalidFeaturesError, ModelLoadError, ModelNotReadyError, PredictionEngine
from ..simulation.demo import build_demo_scenarios, run_simulation


class PredictionRequest(BaseModel):
    features: dict[str, Any]
    source_type: Literal["dataset", "synthetic"] = "synthetic"


class BatchPredictionRequest(BaseModel):
    records: list[PredictionRequest] = Field(min_length=1, max_length=500)


class AlertResponse(BaseModel):
    alert_id: str
    timestamp: str
    predicted_label: int
    prediction: str
    severity: str
    confidence: float | None
    attack_probability: float | None
    detection_method: str
    source_type: str
    explanation: str


class PredictionResponse(BaseModel):
    event_id: str
    predicted_label: int
    prediction: str
    confidence: float | None
    attack_probability: float | None
    probability_is_calibrated: bool
    source_type: str
    alert: AlertResponse | None


class HealthResponse(BaseModel):
    status: str
    model_ready: bool


class ModelStatusResponse(BaseModel):
    ready: bool
    artifact_path: str
    error: str | None = None


class DatasetFeature(BaseModel):
    name: str
    kind: Literal["number", "string"]


class DatasetSampleResponse(BaseModel):
    split: Literal["train", "test"]
    index: int
    source_type: Literal["dataset"] = "dataset"
    dataset_label_for_comparison_only: int
    attack_category: str | None = None
    features: dict[str, Any]


class DetectionPage(BaseModel):
    items: list[dict[str, Any]]
    limit: int
    total: int


EVALUATION_PATH = PROJECT_ROOT / "outputs" / "metrics" / "evaluation.json"
DATASET_VALIDATION_PATH = PROJECT_ROOT / "outputs" / "reports" / "dataset_validation.json"


app = FastAPI(
    title="AI-Powered Cybersecurity Threat Detection System",
    description="Offline UNSW-NB15 binary classification demo; it does not monitor live network traffic.",
    version="1.0.0",
)
_default_origins = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173"
allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", _default_origins).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Accept", "Content-Type"],
)


@lru_cache(maxsize=1)
def get_engine() -> PredictionEngine:
    """Load the local model once per server process."""
    model_path = Path(os.getenv("THREAT_DETECTION_MODEL", str(DEFAULT_MODEL_PATH)))
    return PredictionEngine.from_path(model_path)


def _repository() -> DetectionRepository:
    return DetectionRepository(Path(os.getenv("THREAT_DETECTION_DB", str(DEFAULT_DATABASE_PATH))))


@lru_cache(maxsize=1)
def _dataset_split():
    """Load the two validated local CSVs once for sample/schema/simulation routes."""
    return load_official_split(DEFAULT_TRAIN_PATH, DEFAULT_TEST_PATH)


def _json_scalar(value: Any) -> Any:
    if pd.isna(value):
        return None
    return value.item() if hasattr(value, "item") else value


def _dataset_features(row: pd.Series, columns: list[str]) -> dict[str, Any]:
    return {column: _json_scalar(row[column]) for column in columns}


def _event(result: dict[str, Any], alert: dict[str, Any] | None, request: PredictionRequest, event_id: str) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "alert_id": alert["alert_id"] if alert else None,
        "timestamp": alert["timestamp"] if alert else datetime.now(timezone.utc).isoformat(),
        **result,
        "severity": alert["severity"] if alert else None,
        "detection_method": "supervised_random_forest",
        "source_type": request.source_type,
        "input_summary": {"feature_count": len(request.features)},
    }


@app.get("/", tags=["status"])
def root() -> dict[str, str]:
    return {"message": "Cybersecurity Threat Detection API is running", "status": "ok"}


@app.get("/health", response_model=HealthResponse, tags=["status"])
def health_check() -> dict[str, Any]:
    try:
        get_engine()
        ready = True
    except (ModelNotReadyError, ModelLoadError):
        ready = False
    return {"status": "healthy", "model_ready": ready}


@app.get("/model/status", response_model=ModelStatusResponse, tags=["model"])
def model_status() -> dict[str, Any]:
    artifact_label = (
        "configured local model artifact"
        if os.getenv("THREAT_DETECTION_MODEL")
        else "models/random_forest_pipeline.joblib"
    )
    try:
        get_engine()
        return {"ready": True, "artifact_path": artifact_label, "error": None}
    except (ModelNotReadyError, ModelLoadError) as exc:
        return {"ready": False, "artifact_path": artifact_label, "error": str(exc)}


@app.get("/metrics", tags=["model"])
def evaluation_metrics() -> dict[str, Any]:
    """Return the real saved held-out evaluation report, never live-count estimates."""
    try:
        with EVALUATION_PATH.open(encoding="utf-8") as source:
            return json.load(source)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Saved evaluation metrics are not available yet.") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Saved evaluation metrics could not be read.") from exc


@app.get("/dataset/summary", tags=["dataset"])
def dataset_summary() -> dict[str, Any]:
    """Expose actual local train/test row and attack-category summaries."""
    try:
        if DATASET_VALIDATION_PATH.is_file():
            with DATASET_VALIDATION_PATH.open(encoding="utf-8") as source:
                return json.load(source)
        split = _dataset_split()
        return {
            "training": describe_frame(split.train_frame, "UNSW-NB15 training split"),
            "testing": describe_frame(split.test_frame, "UNSW-NB15 testing split"),
            "input_feature_count": int(split.X_train.shape[1]),
            "excluded_from_features": ["id", "attack_cat", "label"],
            "official_split_preserved": True,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="UNSW-NB15 dataset files are unavailable.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Dataset validation failed: {exc}") from exc


@app.get("/dataset/schema", tags=["dataset"])
def dataset_schema() -> dict[str, Any]:
    """Return the validated predictor names/types; labels and identifiers are excluded."""
    try:
        split = _dataset_split()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="UNSW-NB15 dataset files are unavailable.") from exc
    return {
        "features": [
            {
                "name": name,
                "kind": "number" if pd.api.types.is_numeric_dtype(dtype) else "string",
            }
            for name, dtype in split.X_train.dtypes.items()
        ],
        "excluded_columns": ["id", "attack_cat", "label"],
    }


@app.get("/dataset/sample", response_model=DatasetSampleResponse, tags=["dataset"])
def dataset_sample(
    split_name: Literal["train", "test"] = Query(default="test", alias="split"),
    index: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Return one real record's predictors and a comparison-only dataset label."""
    try:
        dataset = _dataset_split()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="UNSW-NB15 dataset files are unavailable.") from exc
    frame = dataset.train_frame if split_name == "train" else dataset.test_frame
    if index >= len(frame):
        raise HTTPException(status_code=404, detail=f"Sample index must be less than {len(frame)}.")
    row = frame.iloc[index]
    return {
        "split": split_name,
        "index": index,
        "source_type": "dataset",
        "dataset_label_for_comparison_only": int(row["label"]),
        "attack_category": str(row["attack_cat"]) if "attack_cat" in frame.columns else None,
        "features": _dataset_features(row, dataset.X_train.columns.tolist()),
    }


@app.get("/simulation/scenarios", tags=["simulation"])
def simulation_scenarios() -> dict[str, Any]:
    """Describe only scenarios that can be constructed from the present dataset schema."""
    try:
        split = _dataset_split()
        scenarios = build_demo_scenarios(split.train_frame, split.test_frame)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="UNSW-NB15 dataset files are unavailable.") from exc
    except (ValueError, IndexError) as exc:
        raise HTTPException(status_code=422, detail=f"Simulation scenarios are unavailable: {exc}") from exc
    return {
        "items": [
            {
                "scenario": item["scenario"],
                "source_type": item["source_type"],
                "expected_label": item["expected_label"],
                "synthetic_note": item.get("synthetic_note"),
                "modified_features": item.get("modified_features", []),
            }
            for item in scenarios
        ],
        "scope": "Offline dataset records and explicitly synthetic feature variations only.",
    }


@app.post("/simulation/run", tags=["simulation"])
def run_offline_simulation() -> dict[str, Any]:
    """Run the existing safe offline simulation; no shell or network actions are invoked."""
    try:
        engine = get_engine()
        split = _dataset_split()
        results = run_simulation(engine, split.train_frame, split.test_frame, repository=_repository())
    except (ModelNotReadyError, ModelLoadError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="UNSW-NB15 dataset files are unavailable.") from exc
    except (ValueError, IndexError) as exc:
        raise HTTPException(status_code=422, detail=f"Simulation could not run: {exc}") from exc
    counts: dict[str, int] = {}
    for result in results:
        key = str(result["prediction"])
        counts[key] = counts.get(key, 0) + 1
    return {
        "items": results,
        "total": len(results),
        "alert_count": sum(result["alert"] is not None for result in results),
        "prediction_counts": counts,
        "scope": "Offline dataset and explicitly synthetic scenarios; not live monitoring.",
    }


@app.post("/predict", response_model=PredictionResponse, tags=["detection"])
def predict(request: PredictionRequest) -> dict[str, Any]:
    try:
        engine = get_engine()
        result = engine.predict_one(request.features)
        alert = create_alert(result, request.source_type)
        event_id = str(uuid4())
        _repository().add_events([_event(result, alert, request, event_id)])
        return {"event_id": event_id, **result, "source_type": request.source_type, "alert": alert}
    except InvalidFeaturesError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (ModelNotReadyError, ModelLoadError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid record: {exc}") from exc


@app.post("/predict/batch", response_model=list[PredictionResponse], tags=["detection"])
def predict_batch(request: BatchPredictionRequest) -> list[dict[str, Any]]:
    try:
        engine = get_engine()
        predictions = engine.predict_batch([record.features for record in request.records])
        alerts = [create_alert(result, record.source_type) for result, record in zip(predictions, request.records)]
        event_ids = [str(uuid4()) for _ in predictions]
        events = [
            _event(result, alert, record, event_id)
            for result, alert, record, event_id in zip(predictions, alerts, request.records, event_ids)
        ]
        _repository().add_events(events)
        return [
            {"event_id": event_id, **result, "source_type": record.source_type, "alert": alert}
            for event_id, result, record, alert in zip(event_ids, predictions, request.records, alerts)
        ]
    except InvalidFeaturesError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (ModelNotReadyError, ModelLoadError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid record: {exc}") from exc


@app.get("/detections", response_model=DetectionPage, tags=["history"])
def detections(limit: int = Query(default=100, ge=1, le=1000)) -> dict[str, Any]:
    repository = _repository()
    return {"items": repository.list_events(limit), "limit": limit, "total": repository.count_events()}
