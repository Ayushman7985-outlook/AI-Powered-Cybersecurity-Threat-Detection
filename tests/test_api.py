from fastapi.testclient import TestClient
import json
import pandas as pd

from src.threat_detection.api import main
from src.threat_detection.data.loader import DatasetSplit


def test_status_routes_and_missing_model(monkeypatch, tmp_path):
    monkeypatch.setenv("THREAT_DETECTION_MODEL", str(tmp_path / "not-trained.joblib"))
    monkeypatch.setenv("THREAT_DETECTION_DB", str(tmp_path / "history.sqlite3"))
    main.get_engine.cache_clear()
    client = TestClient(main.app)
    assert client.get("/").json()["status"] == "ok"
    assert client.get("/health").json() == {"status": "healthy", "model_ready": False}
    model_status = client.get("/model/status").json()
    assert model_status["ready"] is False
    assert model_status["artifact_path"] == "configured local model artifact"
    assert str(tmp_path) not in model_status["error"]
    response = client.post("/predict", json={"features": {"x": 1}})
    assert response.status_code == 503
    assert client.post("/simulation/run").status_code == 503
    main.get_engine.cache_clear()


def test_api_validation_and_fake_prediction(monkeypatch, tmp_path):
    class Classifier:
        classes_ = [0, 1]

    class Model:
        feature_names_in_ = ["duration", "proto"]
        named_steps = {"classifier": Classifier()}

        def predict(self, frame):
            return [1] * len(frame)

        def predict_proba(self, frame):
            return [[0.1, 0.9]] * len(frame)

    monkeypatch.setenv("THREAT_DETECTION_DB", str(tmp_path / "history.sqlite3"))
    monkeypatch.setattr(main, "get_engine", lambda: main.PredictionEngine(Model()))
    client = TestClient(main.app)
    invalid = client.post("/predict", json={"features": {"duration": 1}})
    assert invalid.status_code == 422
    response = client.post(
        "/predict", json={"features": {"duration": 12, "proto": "tcp"}, "source_type": "synthetic"}
    )
    assert response.status_code == 200
    assert response.json()["prediction"] == "attack"
    assert response.json()["alert"]["source_type"] == "synthetic"
    assert len(client.get("/detections").json()["items"]) == 1
    batch = client.post(
        "/predict/batch",
        json={"records": [
            {"features": {"duration": 12, "proto": "tcp"}, "source_type": "dataset"},
            {"features": {"duration": 14, "proto": "udp"}, "source_type": "synthetic"},
        ]},
    )
    assert batch.status_code == 200
    assert len(batch.json()) == 2
    assert batch.json()[1]["alert"]["source_type"] == "synthetic"
    history = client.get("/detections").json()
    assert len(history["items"]) == history["total"] == 3
    assert client.get("/docs").status_code == 200


def test_dashboard_dataset_metrics_and_cors_routes(monkeypatch, tmp_path):
    frame = pd.DataFrame({
        "id": [1, 2, 3],
        "rate": [1.25, 9.5, 3.0],
        "proto": ["tcp", "udp", "tcp"],
        "attack_cat": ["Normal", "DoS", "Reconnaissance"],
        "label": [0, 1, 1],
    })
    features = frame.drop(columns=["id", "attack_cat", "label"])
    split = DatasetSplit(frame, frame, features, frame["label"], features, frame["label"])
    monkeypatch.setattr(main, "_dataset_split", lambda: split)
    metrics_path = tmp_path / "evaluation.json"
    metrics_path.write_text(json.dumps({"accuracy": 0.9, "testing_rows": 3}), encoding="utf-8")
    validation_path = tmp_path / "validation.json"
    validation_path.write_text(json.dumps({"testing": {"rows": 3}}), encoding="utf-8")
    monkeypatch.setattr(main, "EVALUATION_PATH", metrics_path)
    monkeypatch.setattr(main, "DATASET_VALIDATION_PATH", validation_path)

    client = TestClient(main.app)
    assert client.get("/metrics").json()["testing_rows"] == 3
    assert client.get("/dataset/summary").json()["testing"]["rows"] == 3
    schema = client.get("/dataset/schema").json()
    assert schema["features"] == [
        {"name": "rate", "kind": "number"},
        {"name": "proto", "kind": "string"},
    ]
    sample = client.get("/dataset/sample?split=test&index=1").json()
    assert sample["source_type"] == "dataset"
    assert sample["dataset_label_for_comparison_only"] == 1
    assert "label" not in sample["features"]
    assert client.get("/dataset/sample?split=test&index=30").status_code == 404
    scenarios = client.get("/simulation/scenarios").json()["items"]
    assert {item["scenario"] for item in scenarios} >= {"dos_dataset_record", "recon_dataset_record"}
    cors = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert cors.headers["access-control-allow-origin"] == "http://localhost:5173"