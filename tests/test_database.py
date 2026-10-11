from src.threat_detection.database.repository import DetectionRepository


def test_sqlite_history_stores_minimal_event_metadata(tmp_path):
    repository = DetectionRepository(tmp_path / "history.sqlite3")
    repository.add_events([{
        "event_id": "evt-1", "alert_id": None, "timestamp": "2026-10-11T00:00:00+00:00",
        "predicted_label": 0, "prediction": "normal", "confidence": 0.8,
        "attack_probability": 0.2, "severity": None,
        "detection_method": "supervised_random_forest", "source_type": "dataset",
        "input_summary": {"feature_count": 42},
    }])
    records = repository.list_events()
    assert len(records) == 1
    assert repository.count_events() == 1
    assert records[0]["input_summary"] == {"feature_count": 42}
    assert "features" not in records[0]