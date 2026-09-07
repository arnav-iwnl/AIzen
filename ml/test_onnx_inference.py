#!/usr/bin/env python3
"""Simple ONNX inference tester for v2/runtime/model.onnx

Usage:
  python ml/test_onnx_inference.py "GET /..."

Loads the exported ONNX (`v2/runtime/model.onnx`) and `meta.json`, tokenizes
via `v2.prep.tokenizer.CharTokenizer`, runs ONNX Runtime, and prints results.
"""
import json
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

sys.path.insert(0, "v2")
from prep.tokenizer import CharTokenizer

ROOT = Path(".")
MODEL = ROOT / "v2" / "runtime" / "model.onnx"
META = ROOT / "v2" / "runtime" / "meta.json"


def softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - np.max(x))
    return e / e.sum()


def lookup(map_, idx):
    for k, v in map_.items():
        if int(v) == int(idx):
            return k
    return "unknown"


def run(messages):
    if not MODEL.exists():
        print("Missing ONNX model:", MODEL)
        return 2
    if not META.exists():
        print("Missing meta.json:", META)
        return 2

    meta = json.loads(META.read_text(encoding="utf-8"))
    max_len = int(meta.get("max_len", 200))
    tok = CharTokenizer()

    ids = [tok.encode(m) for m in messages]
    arr = np.array(ids, dtype=np.int64)

    sess = ort.InferenceSession(str(MODEL))
    out = sess.run(None, {"ids": arr})
    # outputs: attack_logits, category_logits, severity_logits
    attack_logits, category_logits, severity_logits = out

    for i, m in enumerate(messages):
        a = attack_logits[i]
        a_sm = softmax(a)
        at_idx = int(np.argmax(a_sm))
        at_conf = float(np.max(a_sm))
        none_idx = int(meta.get("attack_index", {}).get("none", 0))
        is_attack = (at_idx != none_idx) and (at_conf >= float(meta.get("attack_threshold", 0.5)))

        cat_idx = int(np.argmax(category_logits[i]))
        sev_idx = int(np.argmax(severity_logits[i]))

        res = {
            "message": m,
            "is_attack": bool(is_attack),
            "attack_type": lookup(meta["attack_index"], at_idx),
            "attack_confidence": at_conf,
            "category": lookup(meta["category_index"], cat_idx),
            "severity": lookup(meta["severity_index"], sev_idx),
        }
        print(json.dumps(res, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    msgs = sys.argv[1:] or [
        "GET /..%2f..%2fetc%2fpasswd HTTP/1.1",
        "GET /product?id=1%27%20OR%20%271%27=%271 HTTP/1.1",
        "GET /index.html HTTP/1.1",
    ]
    sys.exit(run(msgs))
