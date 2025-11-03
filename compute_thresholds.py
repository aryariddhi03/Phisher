import joblib
import pandas as pd
import numpy as np
from train_model import extract_unified_features
from sklearn.metrics import f1_score

bundle = joblib.load('phishing_models.pkl')
email_model = bundle.get('email_model')
url_model = bundle.get('url_model')
scaler_email = bundle.get('scaler_email')
scaler_url = bundle.get('scaler_url')
email_feature_names = bundle.get('email_feature_names', [])
url_feature_names = bundle.get('url_feature_names', [])

# Load datasets
emails = pd.read_csv('phishing_email.csv')
urls = pd.read_csv('phishing_site_urls.csv')

# Prepare email sample
emails_df = emails.rename(columns={'text_combined': 'content', 'label': 'label'})[['content', 'label']]
emails_s = emails_df.sample(n=min(8000, len(emails_df)), random_state=42)

# Prepare url sample
urls_df = urls.rename(columns={'URL': 'content', 'Label': 'lbl'})[['content', 'lbl']]
urls_df['label'] = urls_df['lbl'].map({'good': 0, 'bad': 1, 'Good': 0, 'Bad': 1, 'GOOD': 0, 'BAD': 1})
urls_df.drop(columns=['lbl'], inplace=True)
urls_s = urls_df.sample(n=min(20000, len(urls_df)), random_state=42)

# Helper to compute probs given features and model

def get_probs(contents, feature_names, scaler, model):
    rows = []
    for c in contents:
        feats = extract_unified_features(str(c))
        # features order is email + url + [is_email, is_url]
        full = pd.DataFrame([feats], columns=email_feature_names + url_feature_names + ["is_email","is_url"]) if (email_feature_names and url_feature_names) else None
        X_sel = full[feature_names] if full is not None else pd.DataFrame([[0]*len(feature_names)], columns=feature_names)
        X_scaled = scaler.transform(X_sel) if scaler is not None else X_sel
        rows.append(float(model.predict_proba(X_scaled)[0][1]))
    return np.array(rows)

best_thr_email = None
if email_model is not None and len(emails_s) > 0:
    y_true_e = emails_s['label'].astype(int).values
    p_e = get_probs(emails_s['content'].tolist(), email_feature_names, scaler_email, email_model)
    thrs = np.linspace(0.2, 0.9, 36)
    f1s = [f1_score(y_true_e, (p_e >= t).astype(int)) for t in thrs]
    best_thr_email = float(thrs[int(np.argmax(f1s))])

best_thr_url = None
if url_model is not None and len(urls_s) > 0:
    y_true_u = urls_s['label'].astype(int).values
    p_u = get_probs(urls_s['content'].tolist(), url_feature_names, scaler_url, url_model)
    thrs = np.linspace(0.2, 0.9, 36)
    f1s = [f1_score(y_true_u, (p_u >= t).astype(int)) for t in thrs]
    best_thr_url = float(thrs[int(np.argmax(f1s))])

if best_thr_email is not None:
    bundle['threshold_email'] = best_thr_email
if best_thr_url is not None:
    bundle['threshold_url'] = best_thr_url

joblib.dump(bundle, 'phishing_models.pkl')
print({
    'threshold_email': best_thr_email,
    'threshold_url': best_thr_url
})
