import re
import math
from collections import Counter

def shannon_entropy(url):
    counts = Counter(url)
    probabilities = [count / len(url) for count in counts.values()]
    return -sum(p * math.log2(p) for p in probabilities)

def extract_features(url):
    url = str(url)

    features = {
        "url_length": len(url),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_slash": url.count('/'),
        "num_digits": sum(c.isdigit() for c in url),
        "has_https": 1 if url.startswith('https') else 0,
        "has_at_symbol": 1 if '@' in url else 0,
        "num_keywords": sum(
            1 for w in ['login','verify','bank','secure','update','account']
            if w in url.lower()
        ),
        "has_ip": 1 if re.match(
            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            url.replace('http://','').replace('https://','')
        ) else 0,
        "entropy": shannon_entropy(url)
    }

    return features
