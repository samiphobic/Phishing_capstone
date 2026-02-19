from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
from features import extract_features

app = Flask(__name__)

model = joblib.load('phishing_model.pkl')

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('url')

    features = extract_features(url)
    df = pd.DataFrame([features])

    prob = model.predict_proba(df)[0][1]
    risk_score = round(prob * 100, 2)

    if risk_score >= 70:
        level = "High Risk"
    elif risk_score >= 40:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    return jsonify({
        "risk_score": risk_score,
        "risk_level": level,
        "features": features
    })

if __name__ == "__main__":
    app.run(debug=True)
