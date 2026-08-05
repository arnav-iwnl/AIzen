"""
AIzen model training — Python side, offline only.

Trains and exports:
  server/ml/model.json   category + severity classifier (char TF-IDF + LogisticRegression)
  server/ml/attack.json  optional attack/normal binary classifier from loghub-labeled data

Inference happens in Node (server/ml/*.js). No Python is needed at runtime.

Run:  npm run train   (from server/)   or   python ml/train.py
"""
import csv
import glob
import json
import os

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABELS = os.path.join(ROOT, "data", "labeled", "patterns.jsonl")
MODEL_OUT = os.path.join(ROOT, "server", "ml", "model.json")
ATTACK_OUT = os.path.join(ROOT, "server", "ml", "attack.json")
TRAINING_DATA = os.path.join(ROOT, "training-data")

VECTORIZER = dict(analyzer="char", ngram_range=(2, 5), lowercase=True, sublinear_tf=True, min_df=2, max_features=20000)


def load_patterns(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            msg = (rec.get("message") or "").strip()
            if msg:
                rows.append((msg, rec["category"], rec["severity"]))
    return rows


def fit_head(X, y, classes):
    clf = LogisticRegression(solver="lbfgs", max_iter=2000, C=5.0)
    clf.fit(X, y)
    return {
        "classes": list(clf.classes_),
        "coef": np.asarray(clf.coef_).tolist(),
        "intercept": np.asarray(clf.intercept_).tolist(),
    }


def evaluate(name, clf, X_test, y_test):
    pred = clf.predict(X_test)
    print(f"  {name}: accuracy={accuracy_score(y_test, pred):.3f} macroF1={f1_score(y_test, pred, average='macro', zero_division=0):.3f}")
    try:
        return confusion_matrix(y_test, pred, labels=clf.classes_)
    except Exception:
        return None


def export_vectorizer(vec):
    # Column-order vocabulary: vocab[i] = feature name at column i
    vocab = [None] * len(vec.vocabulary_)
    for name, idx in vec.vocabulary_.items():
        vocab[idx] = name
    return {
        "ngram_range": list(vec.ngram_range),
        "sublinear_tf": vec.sublinear_tf,
        "lowercase": vec.lowercase,
        "vocab": vocab,
        "idf": np.asarray(vec.idf_).tolist(),
    }


def train_classifier():
    rows = load_patterns(LABELS)
    if not rows:
        raise SystemExit("No labeled patterns. Run `npm run seed:labels` first.")
    print(f"Loaded {len(rows)} labeled patterns")

    texts = [r[0] for r in rows]
    y_cat = [r[1] for r in rows]
    y_sev = [r[2] for r in rows]

    vec = TfidfVectorizer(**VECTORIZER)
    X = vec.fit_transform(texts)

    # Stratify when every class has ≥2 members (rare 1-member classes break it)
    counts = {c: y_cat.count(c) for c in set(y_cat)}
    split_kwargs = dict(test_size=0.25, random_state=42)
    if min(counts.values()) >= 2:
        split_kwargs["stratify"] = y_cat

    X_train, X_test, yc_train, yc_test, ys_train, ys_test = train_test_split(
        X, y_cat, y_sev, **split_kwargs
    )

    cat = LogisticRegression(solver="lbfgs", max_iter=2000, C=5.0)
    cat.fit(X_train, yc_train)
    sev = LogisticRegression(solver="lbfgs", max_iter=2000, C=5.0)
    sev.fit(X_train, ys_train)

    print("Category head:")
    evaluate("category", cat, X_test, yc_test)
    print("Severity head:")
    evaluate("severity", sev, X_test, ys_test)

    model = {
        "kind": "tfidf-logistic",
        "version": 1,
        "vectorizer": export_vectorizer(vec),
        "category": {
            "classes": list(cat.classes_),
            "coef": np.asarray(cat.coef_).tolist(),
            "intercept": np.asarray(cat.intercept_).tolist(),
        },
        "severity": {
            "classes": list(sev.classes_),
            "coef": np.asarray(sev.coef_).tolist(),
            "intercept": np.asarray(sev.intercept_).tolist(),
        },
    }
    with open(MODEL_OUT, "w", encoding="utf-8") as fh:
        json.dump(model, fh)
    print(f"Wrote {MODEL_OUT} ({os.path.getsize(MODEL_OUT)} bytes)")
    return model


def find_attack_rows():
    """Look for a labeled attack/normal CSV (e.g. from loghub OpenSSH)."""
    if not os.path.isdir(TRAINING_DATA):
        return None
    for f in glob.glob(os.path.join(TRAINING_DATA, "**", "*.csv"), recursive=True):
        try:
            with open(f, newline="", encoding="utf-8", errors="ignore") as fh:
                reader = csv.DictReader(fh)
                cols = reader.fieldnames or []
                text_col = next((c for c in cols if c.lower() in ("content", "text", "message", "msg")), None)
                label_col = next((c for c in cols if c.lower() in ("label", "anomaly", "is_attack")), None)
                if not text_col or not label_col:
                    continue
                rows = []
                for r in reader:
                    t = (r.get(text_col) or "").strip()
                    lv = r.get(label_col)
                    if t and lv not in (None, ""):
                        rows.append((t, 1 if float(lv) > 0 else 0))
                if rows:
                    print(f"Attack labels from {f}: {len(rows)} rows")
                    return rows
        except Exception:
            continue
    return None


def train_attack():
    rows = find_attack_rows()
    if not rows:
        print("No labeled attack corpus found (run `npm run pull:loghub`). Skipping attack.json.")
        return

    texts = [r[0] for r in rows]
    y = [r[1] for r in rows]
    vec = TfidfVectorizer(**VECTORIZER)
    X = vec.fit_transform(texts)
    split_kwargs = dict(test_size=0.2, random_state=42)
    if min(y.count(v) for v in set(y)) >= 2:
        split_kwargs["stratify"] = y
    X_train, X_test, y_train, y_test = train_test_split(X, y, **split_kwargs)

    clf = LogisticRegression(multi_class="multinomial", solver="lbfgs", max_iter=2000, C=5.0)
    clf.fit(X_train, y_train)
    print("Attack model:")
    evaluate("attack", clf, X_test, y_test)

    model = {
        "kind": "tfidf-logistic",
        "version": 1,
        "vectorizer": export_vectorizer(vec),
        "attack": {
            "classes": ["normal", "attack"],
            "coef": np.asarray(clf.coef_).tolist(),
            "intercept": np.asarray(clf.intercept_).tolist(),
        },
    }
    with open(ATTACK_OUT, "w", encoding="utf-8") as fh:
        json.dump(model, fh)
    print(f"Wrote {ATTACK_OUT} ({os.path.getsize(ATTACK_OUT)} bytes)")


if __name__ == "__main__":
    os.makedirs(os.path.join(ROOT, "server", "ml"), exist_ok=True)
    train_classifier()
    train_attack()
