# Beginner learning guide

## The problem, simply

Many network connections produce more records than a person can inspect one by one. A network intrusion detection system helps identify records that resemble known malicious activity. This project is a safe offline learning exercise: it receives precomputed UNSW-NB15 rows, classifies them, and demonstrates an alert. It does not connect to or observe a real network.

## What one row means

Think of each CSV row as a compact report about a network flow/connection. Fields such as protocol, duration, packet/byte counts, and connection-count statistics are the **features**—the measured clues. `label` is the target answer: zero for Normal and one for Attack. `attack_cat` gives a more detailed dataset category but would reveal the answer, so it is excluded. `id` identifies a row and is excluded too. Keeping the target or attack category among features would be target leakage: the model would receive the answer rather than learn traffic patterns.

The official split has one training CSV and one testing CSV. The model learns from the training file; the separate test file is held back for a more honest check. The test set is not reused to fit preprocessing or tune the model.

## Machine-learning terms

- **Supervised learning:** learning a mapping from examples and known answers. Here, records and their 0/1 labels are examples and answers.
- **Classification:** selecting a class from a fixed set. The classes here are Normal and Attack.
- **Anomaly detection:** finding unusual records without using the same labeled attack/normal target to teach a classifier. This project does **not** implement this separate method.
- **Preprocessing:** preparing raw columns for a model. Missing numeric values use a median; missing categories use the most common training category.
- **Categorical encoding:** converting values such as `tcp` and `udp` into machine-usable indicator columns. One-hot encoding learns categories from training rows; a new category at prediction time is ignored rather than treated as an error.
- **Random Forest:** a collection of decision trees. Trees ask successive feature-threshold questions; their votes form the final class. A forest is often more stable than one tree, but can still learn dataset artifacts.
- **Prediction score:** the model's estimated support for a class. It is not guaranteed to be a calibrated probability of actual malicious intent.

Scaling numeric values is useful for some distance/gradient models; decision-tree split ordering does not depend on units, so this Random Forest pipeline does not scale numeric columns.

## Evaluation in plain language

For Attack as the positive class, **precision** asks “Of the records called attacks, how many were labeled attacks?” **Recall** asks “Of the known attacks, how many did the model find?” **F1** balances precision and recall. **Accuracy** is all correct predictions divided by all records. A confusion matrix with row/column order Normal, Attack is `[[true normal, false attack], [missed attack, detected attack]]`. False positives create unnecessary investigation; false negatives miss labeled attacks. Since the dataset class proportions are not equal, read precision/recall and confusion counts along with accuracy.

These metrics compare predictions with labels in this dataset, not with all possible real-world attacks.

## Alert and storage behavior

An alert is made separately from classification. No alert is emitted for label 0. An attack prediction produces a timestamped event; a model confidence score at or above 0.8 is assigned the demo tier `high`, otherwise `medium`. It is a visible fixed rule, not a calibrated SOC severity model. Dataset and synthetic sources are marked in response/history. SQLite persists event metadata and a feature count, not input feature values.

## End-to-end walkthrough

1. `scripts/validate_dataset.py` opens both official CSVs, verifies schema/labels, and reports class counts, missing cells, duplicates, and categories.
2. `scripts/train_model.py` removes leakage columns, infers numeric/categorical columns from training data, fits imputers/encoding and the Random Forest on training rows only, and evaluates on the official test rows.
3. If successful, the complete preprocessing/model pipeline is saved; metrics JSON and a confusion matrix are written from those actual predictions.
4. FastAPI loads that saved artifact for a request. Pydantic checks request shape; the engine checks feature names and values; the saved pipeline applies the same preprocessing and predicts.
5. The separate alert policy makes an optional alert, minimal metadata is saved to SQLite, and the response includes class, score, source, and alert.
6. The offline simulation chooses dataset Normal/DoS/Reconnaissance records and explicitly synthetic high-count/rate modifications. It never runs an attack or network operation.

## What the project cannot prove

UNSW-NB15 is an experimental labeled dataset, not a continuous flow feed. Dataset score does not mean a real device is safe or compromised, current threats will be detected, or production false-positive rates will be acceptable. The synthetic cases do not emulate true attacks. There is no separate unsupervised detector, live integration, or authentication-failure signal. The project is for learning and demonstration only.

## Major file guide

| File                                          | Purpose and connection                                                                      |
| --------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `src/threat_detection/data/loader.py`         | CSV load, checks, split, target/feature separation; used by validation/training/simulation. |
| `src/threat_detection/ml/train.py`            | fits preprocessing and Random Forest; writes model and actual evaluation.                   |
| `src/threat_detection/ml/predict.py`          | loads the fitted pipeline; validates single/batch inputs and returns predictions.           |
| `src/threat_detection/detection/alerts.py`    | maps positive predictions into explicit demo alerts.                                        |
| `src/threat_detection/database/repository.py` | stores only minimal event metadata in SQLite.                                               |
| `src/threat_detection/api/main.py`            | HTTP interface to prediction, status, and history.                                          |
| `src/threat_detection/simulation/demo.py`     | offline sample selection and synthetic schema-valid variants.                               |
| `src/threat_detection/visualization.py`       | creates labeled charts from real dataset/evaluation values.                                 |
| `scripts/validate_dataset.py`                 | user-facing validation/report/plot command.                                                 |
| `scripts/train_model.py`                      | command-line training/evaluation entry point.                                               |
| `scripts/predict_sample.py`                   | predicts one chosen held-out row using a real saved model.                                  |
| `scripts/run_simulation.py`                   | requires a real trained artifact and runs offline examples.                                 |

## Stack choice

Pandas/NumPy read and represent tables; scikit-learn provides preprocessing, Random Forest, and metrics; Joblib persists the fitted pipeline; Matplotlib makes static evidence figures; FastAPI/Pydantic/Uvicorn expose validated local HTTP operations; standard-library SQLite stores optional event summaries; Pytest/HTTPX verify behavior. Extra database or packet-capture frameworks are omitted to keep the demonstration small and safe.
