import pandas as pd

from src.threat_detection.simulation.demo import build_demo_scenarios
from src.threat_detection.visualization import save_dataset_figures


def test_simulation_uses_verified_categories_and_labels_synthetic_rows():
    rows = [
        {"id": 1, "label": 0, "attack_cat": "Normal", "rate": 1.0, "sbytes": 10, "spkts": 1,
         "ct_srv_src": 1, "ct_src_dport_ltm": 1, "ct_dst_ltm": 1},
        {"id": 2, "label": 1, "attack_cat": "DoS", "rate": 8.0, "sbytes": 80, "spkts": 8,
         "ct_srv_src": 8, "ct_src_dport_ltm": 8, "ct_dst_ltm": 8},
        {"id": 3, "label": 1, "attack_cat": "Reconnaissance", "rate": 9.0, "sbytes": 90, "spkts": 9,
         "ct_srv_src": 9, "ct_src_dport_ltm": 9, "ct_dst_ltm": 9},
    ]
    frame = pd.DataFrame(rows)
    scenarios = build_demo_scenarios(frame, frame)
    by_name = {scenario["scenario"]: scenario for scenario in scenarios}
    assert by_name["dos_dataset_record"]["source_type"] == "dataset"
    assert by_name["recon_dataset_record"]["expected_label"] == 1
    synthetic = by_name["brute_force_like_repeated_connections_synthetic"]
    assert synthetic["source_type"] == "synthetic"
    assert synthetic["expected_label"] is None
    assert "authentication" in synthetic["synthetic_note"]
    assert "label" not in synthetic["features"]
    assert "id" not in synthetic["features"]


def test_dataset_visualization_writes_actual_figure_files(tmp_path):
    frame = pd.DataFrame({"label": [0, 1, 1], "attack_cat": ["Normal", "DoS", "DoS"]})
    paths = save_dataset_figures(frame, tmp_path)
    assert len(paths) == 2
    assert all(path.is_file() and path.stat().st_size > 0 for path in paths)