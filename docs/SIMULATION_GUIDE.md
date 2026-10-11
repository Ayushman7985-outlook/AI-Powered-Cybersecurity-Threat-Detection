# Safe offline simulation guide

This walkthrough predicts on pre-recorded CSV rows and clearly marked synthetic variants only. It sends no packets and performs no scanning, exploitation, credential attempts, interception, or other activity against a network.

## 1. Prepare the environment

From the repository root in PowerShell, activate the already selected, approved virtual environment and check `python --version`. Do not disable Smart App Control to make a blocked native binary load. Dependency status and the currently verified blocker are in [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

## 2. Validate the dataset

Run `python scripts\validate_dataset.py`. It checks the two exact CSV names in `data\raw`, schema agreement, the binary `label`, and reports shape, dtypes, missing values, duplicates, label counts, and attack categories. It writes `outputs\reports\dataset_validation.json`; if plotting dependencies work, it also creates label/category images under `outputs\figures`.

## 3. Train or load a verified model

Run `python scripts\train_model.py` only when the installed scikit-learn dependencies import successfully in an authorized environment. Training uses the official train file; evaluation uses the untouched official test file. The pipeline must complete and create `models\random_forest_pipeline.joblib` before inference. `GET /model/status` distinguishes a loadable artifact from a missing/broken model. Do not substitute a hand-made model or placeholder score.

## 4. Start the simulation

From the root run `python scripts\run_simulation.py`. It exits clearly if no model loads. On success it prints one object per scenario and writes `outputs\reports\simulation_results.json`, `outputs\figures\simulation_prediction_distribution.png` (if Matplotlib works), and local event metadata to `outputs\detections.sqlite3`.

For one held-out row instead, run `python scripts\predict_sample.py --split test --index 0`. The zero-based index must be within the selected split. It displays the model prediction alongside the dataset label for comparison only; this remains offline data, not live traffic.

## 5. Samples and pattern meaning

The current dataset schema includes `rate`, `sbytes`, `spkts`, and connection-count fields such as `ct_srv_src`, `ct_src_dport_ltm`, and `ct_dst_ltm`. It does not include a direct authentication-failure count.

- **Normal:** a real dataset row with `label=0`.
- **DoS-like example:** a real held-out row whose dataset category is DoS; its label describes the source dataset annotation, not a simulated attack.
- **Reconnaissance-like example:** a real row with category Reconnaissance.
- **Brute-force-like repeated-connection synthetic:** a Normal row with verified count fields increased. “Brute-force-like” describes only the repeated-connection count pattern; this is not a login attack recreation or detector, and no authentication failures are modeled.
- **High-rate synthetic:** a Normal row with selected observed rate/volume fields modified. It is not a packet generator and does not reproduce denial of service.

Synthetic input combinations can be outside the training distribution. Treat the model's response as a demonstration, not scientific validation.

## 6. Observe prediction and alert output

Each report entry has `scenario`, `source_type`, `expected_label` (null for synthetic), `predicted_label`, `prediction`, `confidence`, `attack_probability`, and `alert`. A positive class gives an alert: `high` if the model's maximum-class score is at least 0.8, otherwise `medium`. A zero class has `alert: null`. This score is not calibrated and severity is only a documented demo tier.

## 7. Inspect event history

The simulation uses SQLite and writes no raw record values. Inspect via the API (`GET /detections`) once the API can load the model, or open the database with a local SQLite viewer. Fields include event/alert ID, timestamp, prediction, scores, tier, method, source, and feature-count/scenario summary.

## 8. Generate/inspect graphs

Dataset label/category charts are created by dataset validation. A confusion matrix requires successful model evaluation on actual held-out predictions. The simulation distribution plot requires successful simulation. No graph should be filled with example or placeholder performance numbers.

## 9. Save evidence screenshots

Use Windows Snipping Tool (`Win+Shift+S`) after genuine output is visible. Save sanitized captures in `assets\screenshots\` using the names in `assets\screenshots\README.md`. Hide usernames, full paths, environment variables, and unrelated windows. No screenshots are currently asserted to exist until captured.

## 10. Explain results and limitations

Explain that records are offline flows, categories are dataset labels, and the supervised classifier predicts only the dataset's binary target. Dataset accuracy and synthetic response do not prove real-world security. State whether the model artifact truly loaded, which input source was used, what score was returned, and whether an alert was emitted. If a policy error occurs, report it rather than claiming simulated detection succeeded.
