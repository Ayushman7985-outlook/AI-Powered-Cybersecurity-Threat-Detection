from src.threat_detection.detection.alerts import create_alert
from src.threat_detection.ml.predict import InvalidFeaturesError, ModelNotReadyError, PredictionEngine


class FakeClassifier:
    classes_ = [0, 1]


class FakePipeline:
    feature_names_in_ = ["duration", "proto"]
    named_steps = {"classifier": FakeClassifier()}

    def predict(self, frame):
        return [1 if value > 5 else 0 for value in frame["duration"]]

    def predict_proba(self, frame):
        return [[0.1, 0.9] if value > 5 else [0.85, 0.15] for value in frame["duration"]]


def test_prediction_engine_supports_single_and_batch_without_sklearn():
    engine = PredictionEngine(FakePipeline())
    records = [{"duration": 1, "proto": "tcp"}, {"duration": 8, "proto": "new-category"}]
    predictions = engine.predict_batch(records)
    assert [item["prediction"] for item in predictions] == ["normal", "attack"]
    assert predictions[1]["attack_probability"] == 0.9
    assert predictions[0]["probability_is_calibrated"] is False


def test_feature_validation_rejects_missing_extra_and_nonfinite_values():
    engine = PredictionEngine(FakePipeline())
    for record in (
        {"duration": 1},
        {"duration": 1, "proto": "tcp", "label": 0},
        {"duration": float("nan"), "proto": "tcp"},
        {"duration": 10**1000, "proto": "tcp"},
    ):
        try:
            engine.predict_one(record)
        except InvalidFeaturesError:
            pass
        else:
            raise AssertionError("Invalid input was accepted")


def test_alert_severity_and_source_are_explicit():
    attack = {"predicted_label": 1, "confidence": 0.91, "attack_probability": 0.91}
    alert = create_alert(attack, "synthetic")
    assert alert is not None
    assert alert["severity"] == "high"
    assert alert["source_type"] == "synthetic"
    assert create_alert({"predicted_label": 0}, "dataset") is None


def test_missing_model_is_reported_without_fabricating_predictions(tmp_path):
    try:
        PredictionEngine.from_path(tmp_path / "absent.joblib")
    except ModelNotReadyError as exc:
        assert "artifact is missing" in str(exc)
    else:
        raise AssertionError("A missing model was accepted")