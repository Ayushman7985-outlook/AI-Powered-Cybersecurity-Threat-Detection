# Implementation plan and status

This plan reflects the checked repository, not the broader wish-list of an imaginary live IDS.

## Scope and decisions

- Preserve original workspace, datasets, and both existing virtual environments.
- Keep official UNSW-NB15 training/testing files separate; use `label` as target and drop `id`, `attack_cat`, and `label` from inputs.
- Use a Random Forest pipeline with median numeric imputation, most-frequent categorical imputation, and one-hot encoding. Do not scale tree inputs; trees do not require scale normalization.
- Keep ML imports lazy so data validation, database, API status, and tests can function while native scikit-learn imports are blocked.
- Implement supervised attack classification only. The word “anomaly” is not a claim of unsupervised detection.
- Support API, local SQLite metadata, and offline simulation; no packet capture or active network behavior.
- Do not try another reinstall/version switch or disable Smart App Control without new evidence/authorization.

## Checklist

- [x] Confirm active root; no Git repository existed at inspection and no diagnostic duplicate existed.
- [x] Inspect source, requirements, actual CSV schema, complete split row/label counts, nulls, and duplicate rows.
- [x] Record the original Windows native-extension block and identify a working existing Anaconda environment without changing policy.
- [x] Add dataset validation and leakage-safe data split.
- [x] Add configurable model pipeline, persistence, metrics, and evaluation figure code.
- [x] Add schema-checked single/batch inference and missing-model status.
- [x] Add separated alert rules, privacy-minimal SQLite event history, and offline simulation.
- [x] Add API and automated tests independent of model training.
- [x] Add architecture, beginner, simulation, execution, GitHub, and known-issue documentation.
- [x] Execute dataset validation, generate actual label/category figures, run tests, and verify Uvicorn/HTTP responses.
- [x] Train on the official training split and evaluate on the separate held-out test split in the working Conda environment.
- [x] Save genuine metrics, model, confusion matrix, held-out sample prediction, simulation results, and SQLite events.
- [x] Verify model-ready API status and genuine single/batch API predictions.
- [x] Rerun all tests in the working Conda environment.
- [x] Capture genuine Swagger and model-ready API status screenshots.
- [ ] Verify a newly created Conda environment on this device; its native extension may still be subject to Smart App Control.
- [ ] Capture remaining screenshots and select a project license only after rights review.

## Modules and connections

See [architecture.md](architecture.md) for the actual component diagram and [LEARNING_GUIDE.md](LEARNING_GUIDE.md) for explanations by file.
