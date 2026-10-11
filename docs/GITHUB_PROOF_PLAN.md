# Seven-day GitHub proof plan

Use the days below as an evidence checklist, not a claim about actual dates or past commits. Record completion only after the evidence exists.

## Day 1 — Setup

- [ ] Confirm Python/dependencies and preserve the known application-control blocker.
- [x] Record repository layout and implementation plan.
- Suggested commit: `chore: initialize project structure and tooling`
- Proof: VS Code tree and sanitized environment check.

## Day 2 — Dataset

- [x] Implement CSV schema/label/quality validation and official split preservation.
- [ ] Capture actual validation output and generated category/label plot.
- Suggested commit: `feat: add dataset validation and loading`
- Proof: shape, column list, dtype summary, class/category counts.

## Day 3 — Preprocessing

- [x] Exclude target/category/identifier; add training-only numeric/categorical preprocessing.
- [ ] Verify fitted feature matrix by executing model preprocessing when dependency loads.
- Suggested commit: `feat: implement preprocessing pipeline`
- Proof: logs showing no leakage columns and successful transformed matrix.

## Day 4 — Model

- [x] Implement seeded/class-weighted Random Forest pipeline and persistence.
- [x] Train with the existing Anaconda defaults-channel environment after verifying native estimator imports; original `.venv` remains blocked.
- Suggested commit: `feat: implement intrusion detection model`
- Proof: genuine training log, or sanitized documented Smart App Control blocker.

## Day 5 — Evaluation

- [x] Implement actual metrics, classification report, and confusion matrix output.
- [x] Generate scores from the official held-out test after successful training.
- Suggested commit: `feat: add model evaluation and metrics`
- Proof: metrics JSON, evaluation output, confusion matrix.

## Day 6 — Visualization and simulation

- [x] Implement dataset plots, alert rules, safe simulation, and SQLite history.
- [x] Generate simulation/alert outputs using the genuine fitted model; synthetic examples clearly marked.
- Suggested commit: `feat: add detection visualizations and reports`
- Proof: plot(s), real sample response, and marked synthetic sample response.

## Day 7 — Final upload

- [x] Prepare README, tests, documentation, ignore rules, and screenshot instructions.
- [x] Capture the actual model-ready local API `/docs` and `/model/status` screenshots.
- [ ] Capture remaining screenshots and repository rendering after public creation.
- [ ] Review dataset terms, selected license, Git status, staged files, and secrets.
- Suggested commit: `docs: finalize README and project demonstration`
- Proof: rendered README, project tree, tests, and repository page.

## Safe GitHub setup (PowerShell)

This workspace did not contain a `.git` repository at initial inspection. Before publishing, review every file and dataset term. Create an empty GitHub repository with the proposed name, then from the root:

```powershell
git init
git status --short
git add README.md .gitignore requirements.txt environment.yml docs scripts src tests assets data/raw/README.md outputs/figures/label_distribution.png outputs/figures/attack_category_distribution.png outputs/figures/confusion_matrix.png outputs/figures/simulation_prediction_distribution.png outputs/metrics/evaluation.json outputs/reports/dataset_validation.json outputs/reports/sample_prediction.json outputs/reports/simulation_results.json
git status --short
git diff --cached --stat
git diff --cached --check
git commit -m "chore: prepare cybersecurity detection project"
git branch -M main
git remote add origin https://github.com/<YOUR_ACCOUNT>/ai-powered-cybersecurity-threat-detection.git
git remote -v
git push -u origin main
```

If a remote or `.git` folder exists by then, inspect it before any Git action; do not replace it or force push. Dataset CSVs, model binaries, local database, environments, secrets, and personal path screenshots are excluded. Do not enter credentials in code or terminal transcripts. Select a project license only after deciding code rights and dataset terms; the dataset's license is separate from the repository license.
