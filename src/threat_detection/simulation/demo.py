"""Safe, offline demonstration records derived from the provided dataset."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pandas as pd

from ..data.loader import NON_FEATURE_COLUMNS
from ..database.repository import DEFAULT_DATABASE_PATH, DetectionRepository
from ..detection.alerts import create_alert
from ..ml.predict import PredictionEngine

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPORT_PATH = PROJECT_ROOT / "outputs" / "reports" / "simulation_results.json"
DEFAULT_FIGURE_PATH = PROJECT_ROOT / "outputs" / "figures" / "simulation_prediction_distribution.png"


def build_demo_scenarios(
    train_frame: pd.DataFrame,
    test_frame: pd.DataFrame,
) -> list[dict[str, Any]]:
    """Return dataset samples and clearly synthetic traffic-count variants."""
    features = [column for column in train_frame.columns if column not in NON_FEATURE_COLUMNS]

    def as_record(row: pd.Series) -> dict[str, Any]:
        return {column: _json_value(row[column]) for column in features}

    scenarios: list[dict[str, Any]] = []
    normal = test_frame.loc[test_frame["label"].astype(int) == 0].iloc[0]
    normal_record = as_record(normal)
    scenarios.append({
        "scenario": "normal_dataset_record", "source_type": "dataset",
        "expected_label": 0, "features": normal_record,
    })

    if "attack_cat" in test_frame.columns:
        for category, scenario_name in (("DoS", "dos_dataset_record"), ("Reconnaissance", "recon_dataset_record")):
            matching = test_frame["attack_cat"].astype(str).str.casefold() == category.casefold()
            matches = test_frame.loc[matching]
            if not matches.empty:
                scenarios.append({
                    "scenario": scenario_name, "source_type": "dataset",
                    "expected_label": 1, "features": as_record(matches.iloc[0]),
                })

    # No authentication-failure field exists. These changed examples are not
    # genuine brute-force or denial-of-service traffic.
    for name, columns, multiplier in (
        ("brute_force_like_repeated_connections_synthetic", ("ct_srv_src", "ct_src_dport_ltm", "ct_dst_ltm"), 4),
        ("high_rate_synthetic", ("rate", "sbytes", "spkts"), 3),
    ):
        synthetic = dict(normal_record)
        changed = []
        for column in columns:
            original = synthetic.get(column)
            if isinstance(original, (int, float)):
                synthetic[column] = float(original) * multiplier + multiplier
                changed.append(column)
        if changed:
            scenarios.append({
                "scenario": name, "source_type": "synthetic", "expected_label": None,
                "features": synthetic,
                "synthetic_note": (
                    "A normal dataset row was modified in verified traffic-count/rate "
                    "fields for demonstration only; the dataset has no authentication-failure "
                    "feature and this does not reproduce an attack."
                ),
                "modified_features": changed,
            })
    return scenarios


def run_simulation(
    engine: PredictionEngine,
    train_frame: pd.DataFrame,
    test_frame: pd.DataFrame,
    repository: DetectionRepository | None = None,
    report_path: str | Path = DEFAULT_REPORT_PATH,
    figure_path: str | Path = DEFAULT_FIGURE_PATH,
) -> list[dict[str, Any]]:
    """Run the known offline scenarios, persist minimal history, and save results."""
    scenarios = build_demo_scenarios(train_frame, test_frame)
    predictions = engine.predict_batch([scenario["features"] for scenario in scenarios])
    events: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for scenario, prediction in zip(scenarios, predictions):
        alert = create_alert(prediction, scenario["source_type"])
        event_id = str(uuid4())
        results.append(
            {
                "scenario": scenario["scenario"],
                "source_type": scenario["source_type"],
                "expected_label": scenario["expected_label"],
                **({"synthetic_note": scenario["synthetic_note"]} if "synthetic_note" in scenario else {}),
                **prediction,
                "alert": alert,
            }
        )
        events.append(
            {
                "event_id": event_id,
                "alert_id": alert["alert_id"] if alert else None,
                "timestamp": alert["timestamp"] if alert else datetime.now(timezone.utc).isoformat(),
                **prediction,
                "severity": alert["severity"] if alert else None,
                "detection_method": "supervised_random_forest",
                "source_type": scenario["source_type"],
                "input_summary": {
                    "feature_count": len(scenario["features"]),
                    "scenario": scenario["scenario"],
                },
            }
        )

    (repository or DetectionRepository(DEFAULT_DATABASE_PATH)).add_events(events)
    report = Path(report_path)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(results, indent=2), encoding="utf-8")
    _save_prediction_figure(results, figure_path)
    return results


def _save_prediction_figure(results: list[dict[str, Any]], output_path: str | Path) -> None:
    """Render counts from actual scenario predictions; never use placeholder data."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    counts: dict[str, int] = {}
    for result in results:
        prediction = str(result["prediction"])
        counts[prediction] = counts.get(prediction, 0) + 1
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    figure, axis = plt.subplots(figsize=(6, 4))
    labels = list(counts)
    colors = ["#2a9d8f" if label == "normal" else "#e76f51" for label in labels]
    axis.bar(labels, [counts[label] for label in labels], color=colors)
    axis.set(title="Simulation predictions (offline demo records only)", ylabel="Records")
    figure.tight_layout()
    figure.savefig(destination, dpi=150)
    plt.close(figure)


def _json_value(value: Any) -> Any:
    if pd.isna(value):
        return None
    if hasattr(value, "item"):
        return value.item()
    return value