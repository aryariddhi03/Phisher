## .github/copilot-instructions.md — project-specific guidance for AI coding assistants

Purpose: provide immediately-actionable, repo-specific knowledge so an AI agent is productive without guessing conventions.

- Big picture
  - This is a single-repo ML + web demo for phishing URL detection. Main components:
    - `train_model.py` — feature extraction, training (RandomForest & GradientBoosting), saves models to `phishing_models.pkl` and `phishing_model.pkl` (keys: `random_forest`/`gradient_boosting`, `scaler`, `feature_names`). Feature extractor: `extract_comprehensive_url_features()` (25 features).
    - `app.py` — Streamlit UI that loads the model bundle via `load_model()`, uses feature names from the saved bundle, applies an optional scaler, and shows heuristic analysis via `analyze_url()`.
    - `test_model.py` — simple script that loads `phishing_models.pkl` and runs example URLs through the extractor and model.

- Why files are structured this way
  - Training and feature extraction are colocated so the same feature engineering code is used at training, testing, and in the app. Saved joblib bundles include `feature_names` and `scaler` for reproducible inference.

- Key conventions / patterns to follow
  - Feature shape: models expect exactly the 25 features returned by `extract_comprehensive_url_features()` in `train_model.py` — do not change ordering without updating `feature_names` and retraining.
  - Model files: training writes `phishing_models.pkl` (bundle) and `phishing_model.pkl` (individual RF) to repository root. Code paths assume these files live next to the scripts; keep that convention unless you update `load_model()` and callers.
  - Dataset discovery: `load_kaggle_dataset()` in `train_model.py` looks for files named `phishing_dataset.csv`, `phishing_websites.csv`, `phishing_detection.csv`, `dataset.csv`. Add a dataset filename to this list when adding other CSVs.
  - Heuristic overrides: `app.py` forces a phishing label when an IP is detected in the URL or when `@` is present. Keep that logic in mind when changing thresholds or risk scoring.

- Developer workflows (explicit commands)
  - Install deps: `pip install -r requirements.txt` (use virtualenv/venv)
  - Train models (produces `.pkl` files): `python train_model.py`
  - Run the demo web app: `streamlit run app.py`
  - Run the basic test script: `python test_model.py`

- Debugging & quick checks
  - If `app.py` raises "No trained model found": run `python train_model.py` and confirm `phishing_models.pkl` exists.
  - Model bundle format: inspect with `import joblib; bundle = joblib.load('phishing_models.pkl'); print(bundle.keys())` to verify keys `random_forest`/`feature_names`/`scaler`.
  - Feature mismatch errors typically come from changing `extract_comprehensive_url_features()` without updating `feature_names` saved in model bundles — retrain after any change.

- Small, concrete examples to use in edits/tests
  - Legitimate sample: `https://www.google.com` (used in `app.py` and README)
  - Suspicious sample: `http://google.com.security-verify-account-update.secure-login.info` (exists in `train_model.py` and README)

- Where to change behavior safely
  - To add/remove features: edit `extract_comprehensive_url_features()` and update the `feature_names` list in `train_model.py` **then** retrain and re-save models.
  - To change the UI threshold mapping: modify detection thresholds in `app.py` (the sidebar sensitivity maps to numeric thresholds 0.35/0.50/0.65).

- Integration points / external dependencies
  - Uses `joblib` for model serialization, `scikit-learn` for models, `pandas/numpy` for feature/data handling, and `streamlit` for the web front-end. See `requirements.txt`.

- Minimal test contract for code changes
  - Input: a URL string
  - Output (inference path): features (25 floats) -> optionally scaled -> model prediction and probability -> final decision (boolean) + human-readable signals from `analyze_url()`.

- Quick PR hints for contributors
  - Keep feature ordering stable. If you change features, update training code and include a brief README note describing the change and a regenerated `phishing_models.pkl` (or CI job that trains on a known dataset).
  - Tests are script-based (`test_model.py`) — when adding automated tests, include a deterministic, small fixture dataset and assert model output shapes and that `joblib` bundles contain expected keys.

If anything here is unclear or you want me to include CI examples (GitHub Actions for automatic training or model validation), tell me what CI provider and I’ll add a small workflow file and tests. 
