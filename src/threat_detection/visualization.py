"""Generate labeled dataset and evaluation figures from actual project data."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def save_dataset_figures(train_frame: pd.DataFrame, output_dir: str | Path) -> list[Path]:
    """Plot actual training label and attack-category counts."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    outputs = []
    counts = train_frame["label"].value_counts().sort_index()
    fig, axis = plt.subplots(figsize=(7, 4))
    axis.bar(["Normal (0)", "Attack (1)"], [counts.get(0, 0), counts.get(1, 0)], color=["#2a9d8f", "#e76f51"])
    axis.set_title("UNSW-NB15 training label distribution")
    axis.set_ylabel("Records")
    fig.tight_layout()
    label_path = destination / "label_distribution.png"
    fig.savefig(label_path, dpi=150)
    plt.close(fig)
    outputs.append(label_path)
    if "attack_cat" in train_frame.columns:
        categories = train_frame["attack_cat"].value_counts().sort_values()
        fig, axis = plt.subplots(figsize=(9, 5))
        categories.plot(kind="barh", ax=axis, color="#457b9d")
        axis.set_title("UNSW-NB15 training attack categories")
        axis.set_xlabel("Records")
        fig.tight_layout()
        category_path = destination / "attack_category_distribution.png"
        fig.savefig(category_path, dpi=150)
        plt.close(fig)
        outputs.append(category_path)
    return outputs


def save_confusion_matrix(matrix: list[list[int]], output_path: str | Path) -> Path:
    """Render a confusion matrix already computed from genuine test predictions."""
    import numpy as np
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    display = ConfusionMatrixDisplay(np.asarray(matrix, dtype=int), display_labels=["Normal", "Attack"])
    display.plot(values_format="d", cmap="Blues")
    plt.title("UNSW-NB15 held-out test confusion matrix")
    plt.tight_layout()
    plt.savefig(destination, dpi=150)
    plt.close()
    return destination