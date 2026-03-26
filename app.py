import os
import json
import joblib
import numpy as np
import traceback
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
from train_model import extract_features, FEATURE_ORDER

app  = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# Whitelist — returns score 0 immediately,
# model is never called for these domains.
# ─────────────────────────────────────────────
WHITELIST = {
    "google.com", "github.com", "microsoft.com", "apple.com",
    "wikipedia.org", "youtube.com", "facebook.com", "linkedin.com",
    "amazon.com",    "discord.com",  "twitter.com",  "x.com",
    "reddit.com",    "spotify.com",  "netflix.com",  "twitch.tv",
    "notion.so",     "slack.com",    "zoom.us",       "dropbox.com",
    "cloudflare.com","stripe.com",   "shopify.com",   "instagram.com",
    "tiktok.com",    "pinterest.com","stackoverflow.com","openai.com",
    "anthropic.com", "adobe.com",    "salesforce.com","hubspot.com",
}

# ─────────────────────────────────────────────
# Load model once at startup
# ─────────────────────────────────────────────
try:
    model = joblib.load("strongest_phishing_model.pkl")
    print("✅ XGBoost model loaded.")
    print(f"📊 Expects {len(FEATURE_ORDER)} features.")
except Exception as e:
    print(f"❌ Model load failed: {e}")
    model = None

try:
    with open("model_metadata.json") as f:
        MODEL_META = json.load(f)
    print(f"📋 Model accuracy: {MODEL_META.get('accuracy')}%")
except Exception:
    MODEL_META = {}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def get_domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_whitelisted(domain: str) -> bool:
    if domain in WHITELIST:
        return True
    # match subdomains: mail.google.com → google.com
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in WHITELIST:
            return True
    return False


def risk_level(score: int) -> str:
    if score >= 7:
        return "HIGH RISK"
    if score >= 4:
        return "MEDIUM RISK"
    return "LOW RISK"


def get_explanation(feat: dict, score: int, whitelisted: bool) -> str:
    if whitelisted:
        return "Trusted domain — verified safe."
    reasons = []
    if feat["has_https"] == 0:
        reasons.append("no HTTPS encryption")
    if feat["is_ip_domain"] == 1:
        reasons.append("raw IP address used as domain")
    if feat["num_keywords"] > 0:
        reasons.append("contains sensitive keywords")
    if feat["entropy"] > 4.5:
        reasons.append("high URL randomness (entropy)")
    if feat["tld_suspicious"] == 1:
        reasons.append("suspicious top-level domain")
    if feat["has_at_symbol"] == 1:
        reasons.append("@ symbol trick detected")
    if not reasons:
        return "No strong phishing signals detected."
    return "Flagged for: " + ", ".join(reasons[:3]) + "."


def build_ui_analysis(feat: dict) -> dict:
    return {
        "Encryption":  {"value": "HTTPS" if feat["has_https"] else "No HTTPS",
                        "warning": not feat["has_https"]},
        "Domain type": {"value": "IP address" if feat["is_ip_domain"] else "Standard",
                        "warning": bool(feat["is_ip_domain"])},
        "Entropy":     {"value": f"{feat['entropy']:.2f} bits",
                        "warning": feat["entropy"] > 4.5},
        "Keywords":    {"value": f"{feat['num_keywords']} found" if feat["num_keywords"] else "None",
                        "warning": feat["num_keywords"] > 0},
        "Subdomains":  {"value": str(feat["num_subdomains"]),
                        "warning": feat["num_subdomains"] > 3},
        "TLD":         {"value": "Suspicious" if feat["tld_suspicious"] else "Normal",
                        "warning": bool(feat["tld_suspicious"])},
        "@ symbol":    {"value": "Present" if feat["has_at_symbol"] else "None",
                        "warning": bool(feat["has_at_symbol"])},
        "URL length":  {"value": str(feat["url_length"]),
                        "warning": feat["url_length"] > 75},
    }


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if not model:
        return jsonify({"error": "Model not loaded. Run train_model.py first."}), 500

    try:
        data = request.get_json(force=True)
        url  = (data.get("url") or "").strip()

        if not url:
            return jsonify({"error": "URL is empty"}), 400

        # ── Block non-HTTP schemes ────────────────────────────────────
        INVALID_SCHEMES = ("javascript:", "data:", "vbscript:", "file:")
        if any(url.lower().startswith(s) for s in INVALID_SCHEMES):
            return jsonify({
                "risk_score":       8,
                "risk_level":       "HIGH RISK",
                "explanation":      "Non-HTTP scheme detected — possible browser exploit.",
                "feature_analysis": {},
            })

        has_valid_structure = url.startswith(("http://", "https://", "ftp://"))

        # ── Whitelist fast-path ───────────────────────────────────────
        domain      = get_domain(url)
        whitelisted = is_whitelisted(domain)

        if whitelisted:
            feat_dict = extract_features(url)
            return jsonify({
                "risk_score":       0,
                "risk_level":       "SAFE",
                "explanation":      get_explanation(feat_dict, 0, True),
                "feature_analysis": build_ui_analysis(feat_dict),
            })

        # ── Run model ─────────────────────────────────────────────────
        feat_dict    = extract_features(url)
        features_arr = np.array(
            [feat_dict.get(f, 0) for f in FEATURE_ORDER]
        ).reshape(1, -1)

        prob_malicious = float(model.predict_proba(features_arr)[0][1])
        score = prob_malicious * 10

        # ── Dampening for malformed / ambiguous input ─────────────────
        if not has_valid_structure:
            score = min(score, 6.0)
            prefix = "Not a standard URL. "
        else:
            prefix = ""

        # Credentials in URL — cap at 7
        try:
            p = urlparse(url)
            if p.username or p.password:
                score = min(score, 7.0)
        except Exception:
            pass

        final_score = int(round(min(max(score, 0.0), 10.0)))

        return jsonify({
            "risk_score":       final_score,
            "risk_level":       risk_level(final_score),
            "explanation":      prefix + get_explanation(feat_dict, final_score, False),
            "feature_analysis": build_ui_analysis(feat_dict),
        })

    except Exception:
        print(traceback.format_exc())
        return jsonify({"error": "Server error during analysis"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)