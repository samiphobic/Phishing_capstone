import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib
from features import extract_features

def train():
    df = pd.read_csv('balanced_urls.csv')

    X = pd.DataFrame([extract_features(u) for u in df['url']])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        random_state=42
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    auc = roc_auc_score(y_test, model.predict_proba(X_test)[:,1])
    print("ROC-AUC:", auc)

    joblib.dump(model, 'phishing_model.pkl')
    print("Model saved.")

if __name__ == "__main__":
    train()
