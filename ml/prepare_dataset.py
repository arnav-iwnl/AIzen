"""
Prepare a small synthetic dataset of web attack examples for quick experiments.
Writes `ml/data/dataset.jsonl` with fields: id, text, label

Usage:
  python ml/prepare_dataset.py --out ml/data/dataset.jsonl --counts 200

This file is a helper to bootstrap data for the transformer training pipeline.
"""
import argparse
import json
import os
import random
import urllib.parse

SAMPLES = {
    "xss": [
        "GET /search?q=<script>alert(1)</script> HTTP/1.1",
        "GET /profile?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1",
        "GET /?q=\"%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1",
        "GET /x?param=%%3Csvg%20onload=alert(1)%%3E HTTP/1.1",
    ],
    "sqli": [
        "GET /product?id=1 OR 1=1 -- HTTP/1.1",
        "POST /login.php HTTP/1.1\nusername=admin' OR '1'='1&password=whatever",
        "GET /search?q=UNION+SELECT+password+FROM+users HTTP/1.1",
    ],
    "lfi": [
        "GET /download?file=../../../../etc/passwd HTTP/1.1",
        "GET /view?path=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1",
        "GET /?page=/proc/self/environ HTTP/1.1",
    ],
    "bruteforce": [
        "POST /login HTTP/1.1\nusername=admin&password=123456",
        "POST /wp-login.php HTTP/1.1\nlog=admin&pwd=1234",
        "POST /auth HTTP/1.1\nusername=admin&password=admin",
    ],
    "scanner": [
        "GET /admin/ HTTP/1.1\nUser-Agent: nikto",
        "GET /phpmyadmin/ HTTP/1.1\nUser-Agent: sqlmap",
        "GET / HTTP/1.1\nUser-Agent: Acunetix",
    ],
    "benign": [
        "GET /index.html HTTP/1.1",
        "GET /about HTTP/1.1",
        "GET /images/logo.png HTTP/1.1",
        "GET /profile?id=42 HTTP/1.1",
    ],
}

AUGMENTERS = [
    lambda s: s,
    lambda s: s.replace(" ", "  "),
    lambda s: s.replace("/", "/"),
]


def url_encode_variants(s):
    # Create variants with URL-encoded payloads in query params
    if "?" in s:
        parts = s.split("?", 1)
        base, query = parts[0], parts[1]
        encoded = urllib.parse.quote_plus(query)
        return [s, f"{base}?{encoded} HTTP/1.1"]
    return [s]


def generate(out_path, counts=200):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    rows = []
    labels = list(SAMPLES.keys())
    # distribute counts across labels (more benign than attacks)
    weights = {
        "xss": 1,
        "sqli": 1,
        "lfi": 1,
        "bruteforce": 1,
        "scanner": 1,
        "benign": 3,
    }
    total_weight = sum(weights.values())
    for i in range(counts):
        # choose label
        r = random.random() * total_weight
        cum = 0
        for lab, w in weights.items():
            cum += w
            if r <= cum:
                label = lab
                break
        sample = random.choice(SAMPLES[label])
        variants = url_encode_variants(sample)
        sample = random.choice(variants)
        # small random obfuscation
        if random.random() < 0.3:
            sample = sample.replace("/", "%2F")
        rows.append({"id": f"s{i}", "text": sample, "label": label})

    with open(out_path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="ml/data/dataset.jsonl")
    p.add_argument("--counts", type=int, default=200)
    args = p.parse_args()
    generate(args.out, args.counts)
