"""Transparent, demonstration-only alert rules for binary model predictions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def create_alert(
    prediction: dict[str, Any],
    source_type: str,
    detection_method: str = "supervised_random_forest",
) -> dict[str, Any] | None:
    """Create alerts for attack predictions; severity is a demo confidence tier."""
    if source_type not in {"dataset", "synthetic"}:
        raise ValueError("source_type must be 'dataset' or 'synthetic'.")
    if int(prediction["predicted_label"]) != 1:
        return None
    confidence = prediction.get("confidence")
    severity = "high" if confidence is not None and confidence >= 0.8 else "medium"
    return {
        "alert_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "predicted_label": 1,
        "prediction": "attack",
        "severity": severity,
        "confidence": confidence,
        "attack_probability": prediction.get("attack_probability"),
        "detection_method": detection_method,
        "source_type": source_type,
        "explanation": (
            "The supervised model classified this record as attack traffic. "
            "The confidence tier is a demonstration rule, not calibrated SOC severity."
        ),
    }