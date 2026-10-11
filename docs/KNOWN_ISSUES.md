# Known issues and environment blocker

## Windows Smart App Control blocks the original pip virtual environment

The selected Smart App Control state reported by the user is **On**. Event Viewer evidence supplied by the user includes Code Integrity event 3077 for scikit-learn's `_vector_sentinel.cp313-win_amd64.pyd`, policy name `VerifiedAndReputableDesktop`, policy ID `27555.1000.240208`, status `0xc0e90002`, requested signing level 2 and validated level 1. Related event 3118 had an empty Defender threat name. This is evidence of Windows application-control enforcement; it is not evidence that the package is malware.

The original `.venv` (Python 3.13.15 x64, NumPy 2.5.4, SciPy 1.18.1, scikit-learn 1.9.1) still fails at `sklearn.utils._vector_sentinel.cp313-win_amd64.pyd`: `ImportError: DLL load failed while importing _vector_sentinel: An Application Control policy has blocked this file.` The earlier Python 3.12 diagnostic reportedly failed at NumPy `_umath_linalg.cp312-win_amd64.pyd`; a later focused check imported NumPy successfully but scikit-learn failed at `_sfc64`. The location/version variation did not establish that changing Python version resolves the policy.

Installed metadata identifies a pip-installed `cp313-cp313-win_amd64` wheel and contains no `direct_url.json`, so the original installation source is not recorded. A read-only comparison against [PyPI's published scikit-learn 1.9.1 release metadata](https://pypi.org/pypi/scikit-learn/1.9.1/json) was completed: PyPI publishes a non-yanked matching CPython 3.13 Windows x64 wheel; its public SHA-256 was independently matched against the downloaded wheel, and the installed `_vector_sentinel.cp313-win_amd64.pyd` matched the wheel member byte-for-byte and its `RECORD` digest. The extension's SHA-256 is `8a52b5d06fe0c14def7703e8da25ffd64207276768b29330d83a1805305a2b2a`; the wheel's SHA-256 is `2070f271e5375dc42c6bb93b461ab1c0aa5841d4009267e0cfd95a39dca94a43`. Windows `Get-AuthenticodeSignature` reports the `.pyd` as `NotSigned`; PyPI metadata reports no wheel signature. The wheel was only checksum-verified and inspected as a ZIP archive, never installed or executed. This confirms a match to the public package artifact, not that the application-control policy should allow it. It does not indicate malware.

No binaries were force-loaded. No exclusions, policy edits, elevation, or environment deletions were used. No reinstall was repeated in the blocked venv.

### Consequences

### Safe next action

For this project run, the already successful Conda base was used. Continue only if it is permitted by the device owner/organization, or create a separate environment from `environment.yml` and smoke-test the estimator import first. The fresh spec has not been created/tested. For the original blocked `.venv`, the safe next action remains administrator/Microsoft review of its Code Integrity decision; do not weaken or bypass Windows policy.
For this project run, use the tested existing Anaconda environment or a separately approved managed environment, following [the README setup section](../README.md). A fresh Conda environment is described in `environment.yml`; it has not been created/tested here, so verify its compiled imports under the current device policy before training. For continued use of the original `.venv`, have the authorized administrator/Microsoft support review the specific Code Integrity event and unsigned extension. Keep Smart App Control enabled, do not bypass policy, and do not upload sensitive data to an unapproved hosted service.

## Dataset redistribution

The raw CSVs are locally present but ignored by Git. Confirm the current UNSW-NB15 terms before distributing them. The repository documents the official source and local placement instead of bundling the data.

## Model artifact trust

Joblib uses pickle-based serialization. Loading an untrusted `.joblib` file can execute code in the API process. The API should load only a locally trained or otherwise independently verified artifact; do not point `THREAT_DETECTION_MODEL` at an unknown download.
