import pandas as pd
import pytest

from src.threat_detection.data.loader import describe_frame, load_csv, load_official_split, validate_frame


def test_loader_excludes_label_category_and_identifier(tmp_path):
    rows = {"id": [1, 2], "value": [0.1, 0.2], "proto": ["tcp", "udp"], "attack_cat": ["Normal", "DoS"], "label": [0, 1]}
    train, test = tmp_path / "train.csv", tmp_path / "test.csv"
    pd.DataFrame(rows).to_csv(train, index=False)
    pd.DataFrame(rows).to_csv(test, index=False)
    split = load_official_split(train, test)
    assert split.X_train.columns.tolist() == ["value", "proto"]
    assert split.y_train.tolist() == [0, 1]
    assert split.X_test.columns.tolist() == split.X_train.columns.tolist()


def test_missing_file_and_invalid_target_are_reported(tmp_path):
    with pytest.raises(FileNotFoundError, match="does not exist"):
        load_csv(tmp_path / "absent.csv")
    with pytest.raises(ValueError, match="only 0 and 1"):
        validate_frame(pd.DataFrame({"feature": [1], "label": [2]}))


def test_dataset_summary_reports_quality_fields():
    report = describe_frame(pd.DataFrame({"label": [0, 1], "attack_cat": ["Normal", "DoS"]}), "fixture")
    assert report["rows"] == 2
    assert report["missing_values"] == 0
    assert report["label_distribution"] == {"0": 1, "1": 1}