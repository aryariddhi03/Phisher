import pandas as pd
import numpy as np
import joblib
import sys
# Ensure function symbols exist for unpickling
import train_model  # noqa: F401
from train_model import extract_unified_features
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

# Map required functions into __main__ for unpickling compatibility
sys.modules['__main__'].extract_comprehensive_url_features = train_model.extract_comprehensive_url_features
sys.modules['__main__'].extract_unified_features = train_model.extract_unified_features
sys.modules['__main__'].extract_email_features = train_model.extract_email_features

# Load model bundle
bundle = joblib.load('phishing_models.pkl')
model = bundle['random_forest']
scaler = bundle['scaler']
feature_names = bundle['feature_names']

# Load datasets
emails = pd.read_csv('phishing_email.csv')
urls = pd.read_csv('phishing_site_urls.csv')

# Prepare email dataframe
emails_df = emails.rename(columns={'text_combined': 'content', 'label': 'label'})[['content', 'label']]
emails_df['type'] = 'email'

# Prepare URL dataframe
urls_df = urls.rename(columns={'URL': 'content', 'Label': 'lbl'})[['content', 'lbl']]
urls_df['label'] = urls_df['lbl'].map({'good': 0, 'bad': 1, 'Good': 0, 'Bad': 1, 'GOOD': 0, 'BAD': 1})
urls_df.drop(columns=['lbl'], inplace=True)
urls_df['type'] = 'url'

# Sample manageable subsets
emails_s = emails_df.sample(n=min(5000, len(emails_df)), random_state=42)
urls_s = urls_df.sample(n=min(10000, len(urls_df)), random_state=42)
combined = pd.concat([emails_s, urls_s], ignore_index=True)

# Build features
features_list = []
for c in combined['content'].astype(str).tolist():
    feats = extract_unified_features(c)
    if len(feats) < len(feature_names):
        feats = feats + [0.0] * (len(feature_names) - len(feats))
    elif len(feats) > len(feature_names):
        feats = feats[:len(feature_names)]
    features_list.append(feats)

X = pd.DataFrame(features_list, columns=feature_names)
y = combined['label'].astype(int).values

# Scale
X_scaled = scaler.transform(X)

# Predict
proba = None
try:
    proba = model.predict_proba(X_scaled)[:, 1]
except Exception:
    pass
pred = model.predict(X_scaled)

# Metrics
acc = accuracy_score(y, pred)
prec = precision_score(y, pred, zero_division=0)
rec = recall_score(y, pred, zero_division=0)
f1 = f1_score(y, pred, zero_division=0)
cm = confusion_matrix(y, pred)
print(f"Samples evaluated: {len(y)} (emails={len(emails_s)}, urls={len(urls_s)})")
print("Confusion Matrix:\n", cm)
print(f"Accuracy: {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall: {rec:.4f}")
print(f"F1: {f1:.4f}")
if proba is not None:
    try:
        auc = roc_auc_score(y, proba)
        print(f"AUC-ROC: {auc:.4f}")
    except Exception:
        pass
