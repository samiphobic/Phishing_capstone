import pandas as pd
import numpy as np
import re
import math
import joblib
import json
import xgboost as xgb
from collections import Counter
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
PHISH_KEYWORDS = [
    "login", "verify", "bank", "secure", "update", "account",
    "confirm", "webscr", "signin", "paypal", "office365", "outlook"
]
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".info",
    ".site", ".icu", ".monster", ".work"
]

# Strict feature order — must match exactly in app.py
FEATURE_ORDER = [
    "url_length", "num_dots", "num_hyphens", "num_slash", "num_digits",
    "has_https", "has_at_symbol", "num_keywords", "has_ip", "entropy",
    "num_subdomains", "tld_suspicious", "has_encoded_chars",
    "has_port", "path_length", "query_length", "num_query_params",
    "is_ip_domain", "digit_ratio", "special_char_count"
]


# ─────────────────────────────────────────────
# Feature Extraction
# ─────────────────────────────────────────────
def shannon_entropy(url: str) -> float:
    if not url or not isinstance(url, str):
        return 0.0
    counts = Counter(url)
    probabilities = [count / len(url) for count in counts.values()]
    return -sum(p * math.log2(p) for p in probabilities)


def extract_features(url: str) -> dict:
    url = str(url).lower().strip()
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        try:
            has_port = 1 if parsed.port is not None else 0
        except ValueError:
            has_port = 1
    except Exception:
        hostname = ""
        has_port = 0
        parsed = None

    is_ip_domain = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    parts = hostname.split(".")
    num_subdomains = max(len(parts) - 2, 0)
    digits = sum(c.isdigit() for c in url)
    special_chars = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url))

    return {
        "url_length":         len(url),
        "num_dots":           url.count("."),
        "num_hyphens":        url.count("-"),
        "num_slash":          url.count("/"),
        "num_digits":         digits,
        "has_https":          1 if url.startswith("https") else 0,
        "has_at_symbol":      1 if "@" in url else 0,
        "num_keywords":       sum(1 for kw in PHISH_KEYWORDS if kw in url),
        "has_ip":             1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", hostname) else 0,
        "entropy":            shannon_entropy(url),
        "num_subdomains":     num_subdomains,
        "tld_suspicious":     1 if any(hostname.endswith(t) for t in SUSPICIOUS_TLDS) else 0,
        "has_encoded_chars":  1 if "%" in url else 0,
        "has_port":           has_port,
        "path_length":        len(parsed.path) if parsed and parsed.path else 0,
        "query_length":       len(parsed.query) if parsed and parsed.query else 0,
        "num_query_params":   len(parsed.query.split("&")) if parsed and parsed.query else 0,
        "is_ip_domain":       is_ip_domain,
        "digit_ratio":        digits / len(url) if len(url) > 0 else 0,
        "special_char_count": special_chars,
    }


# ─────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────
def train():
    print("🚀 Starting XGBoost Training Pipeline...")

    # 1. Load data
    try:
        df = pd.read_csv("balanced_urls.csv").dropna(subset=["url"])
        print(f"📊 Loaded {len(df):,} URLs")
        print(f"   Class balance: {df['result'].value_counts().to_dict()}")
    except Exception as e:
        print(f"❌ Could not load balanced_urls.csv — {e}")
        return

    # 2. Feature extraction
    print("⚙️  Extracting features...")
    X = pd.DataFrame([extract_features(u) for u in df["url"]])[FEATURE_ORDER]
    y = df["result"].values  # 0 = benign, 1 = malicious

    # 3. Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"✂️  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # 4. Class imbalance weight
    neg = int(np.sum(y_train == 0))
    pos = int(np.sum(y_train == 1))
    spw = round(neg / pos, 2) if pos > 0 else 1.0
    print(f"⚖️  scale_pos_weight = {spw}")

    # 5. Model
    model = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=1,
        reg_lambda=2,
        scale_pos_weight=spw,
        eval_metric="logloss",
        use_label_encoder=False,
        random_state=42,
        seed=42,
        early_stopping_rounds=30,
    )

    # 6. Fit
    print("🧠 Training...")
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=50
    )

    # 7. Save
    joblib.dump(model, "strongest_phishing_model.pkl")
    print("💾 Saved → strongest_phishing_model.pkl")

    # 8. Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average="weighted")
    print(f"\n✅ Accuracy : {acc * 100:.2f}%")
    print(f"✅ F1 Score : {f1 * 100:.2f}%")
    print("\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

    # 9. Feature importance
    importances = model.feature_importances_
    feat_imp = sorted(zip(FEATURE_ORDER, importances), key=lambda x: x[1], reverse=True)
    print("\n🏆 Top 10 Features:")
    for name, score in feat_imp[:10]:
        bar = "█" * int(score * 200)
        print(f"  {name:<25} {score:.4f}  {bar}")

    # 10. Save metadata
    metadata = {
        "accuracy":          round(acc * 100, 2),
        "f1_score":          round(f1 * 100, 2),
        "n_estimators_used": int(model.best_iteration) if hasattr(model, "best_iteration") else 500,
        "max_depth":         6,
        "features":          FEATURE_ORDER,
        "top_features":      [name for name, _ in feat_imp[:5]],
    }
    with open("model_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    print("📁 Metadata saved → model_metadata.json")

    # 11. Sanity check
    print("\n🔍 Sanity Check:")
    test_urls = [
        ("https://discord.com/",                    "LOW  (< 4)"),
        ("https://github.com/login",                "LOW  (< 4)"),
        ("https://www.google.com/",                 "LOW  (< 4)"),
        ("http://paypal-secure-login.xyz/verify",   "HIGH (>= 7)"),
        ("http://192.168.1.1/bank/signin",          "HIGH (>= 7)"),
        ("http://microsofft-secure.online/verify",  "HIGH (>= 7)"),
        ("http://login-paypal.com@evil.xyz/webscr", "HIGH (>= 7)"),
    ]
    for url, expected in test_urls:
        feats = pd.DataFrame([extract_features(url)])[FEATURE_ORDER]
        prob  = model.predict_proba(feats)[0][1]
        raw   = int(round(min(max(prob * 10, 0), 10)))
        flag  = "✅" if (
            ("LOW"  in expected and raw < 4) or
            ("HIGH" in expected and raw >= 7)
        ) else "⚠️ "
        print(f"  {flag} {raw}/10  {url[:60]:<60} (expected {expected})")


if __name__ == "__main__":
    train()