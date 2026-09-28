"""Eval runner — held-out metrics + mixed-ratio sweep for AIzen v2.

Evaluates the exported ONNX (or the torch checkpoint) and writes
v2/data/eval_report.json, reporting attack P/R/F1 over a range of attack ratios
(the mixed scenario). The final production gate is enforced by the Node
mixed_benchmark.js; this provides the fuller numbers.

Run: python -m eval.eval_runner
"""
import json
import os
import sys

import numpy as np

import config


def _load_onnx():
    import onnxruntime as ort
    return ort.InferenceSession(config.ONNX_PATH, providers=["CPUExecutionProvider"])


def _tokenize_ids(text):
    # Use the real tokenizer rather than a third copy of the rules. This one
    # truncated at [:MAX_LEN] and therefore disagreed with the runtime on any
    # string longer than the window, silently scoring the export on different
    # sequences than it serves.
    from prep.tokenizer import CharTokenizer
    return CharTokenizer().encode(text)


def _softmax(v):
    v = np.asarray(v, dtype=np.float32)
    e = np.exp(v - v.max())
    return e / e.sum()


def _load_ballot(syn=True):
    path = config.TRAIN_BALLOT.replace(".jsonl", ".synth.jsonl") if syn else config.TRAIN_BALLOT
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def _attack_label(rec, meta):
    at = rec.get("attack_type") or "none"
    if at not in meta["attack_index"]:
        at = "other" if rec.get("is_attack") else "none"
    return int(at != "none")


def main():
    config.ensure_dirs()
    if not os.path.exists(config.ONNX_PATH):
        print(f"[eval] missing {config.ONNX_PATH}. Run export_onnx first.")
        return 1
    with open(config.META_PATH, encoding="utf-8") as fh:
        meta = json.load(fh)
    threshold = meta["attack_threshold"]

    rows = _load_ballot(syn=True)
    rng = np.random.RandomState(0)
    rows = rng.permutation(rows)

    # fixed 20% held-out test (from the SYNTH ballot)
    test = rows[int(len(rows) * 0.9):]

    session = _load_onnx()

    def predict(msgs):
        arr = np.array([_tokenize_ids(m) for m in msgs], dtype=np.int64)
        out = session.run(None, {"ids": arr})
        probs = []
        for i in range(len(msgs)):
            probs.append(float(_softmax(out[0][i]).max()))
        return probs

    # ── held-out attack metrics ──────────────────────────────────────────
    msgs = [r["message"] for r in test]
    probs = predict(msgs)
    labels = [_attack_label(r, meta) for r in test]
    pred = (np.array(probs) >= threshold).astype(int)
    y = np.array(labels)

    tp = int(np.sum((y == 1) & (pred == 1)))
    fp = int(np.sum((y == 0) & (pred == 1)))
    fn = int(np.sum((y == 1) & (pred == 0)))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    report = {
        "heldout": {"n": int(len(test)), "attack": int(y.sum()),
                    "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                    "threshold": threshold},
        "mixed_sweep": {},
    }

    # ── mixed ratio sweep ────────────────────────────────────────────────
    benign = [r for r in rows if not r["is_attack"]]
    attacks = [r for r in rows if r["is_attack"]]
    rng2 = np.random.RandomState(1)
    for ratio in [0.01, 0.03, 0.05, 0.10]:
        a_n = max(1, int(len(attacks) * ratio))
        a_pool = rng2.permutation(attacks)[:a_n]
        pool = list(a_pool) + list(rng2.permutation(benign)[: len(benign)])
        m = [r["message"] for r in pool]
        p = predict(m)
        labels = [_attack_label(r, meta) for r in pool]
        pp = (np.array(p) >= threshold).astype(int)
        yy = np.array(labels)
        tpp = int(np.sum((yy == 1) & (pp == 1)))
        fpp = int(np.sum((yy == 0) & (pp == 1)))
        fnn = int(np.sum((yy == 1) & (pp == 0)))
        r_ = tpp / (tpp + fnn) if tpp + fnn else 0.0
        bprec = (len(pool) - yy.sum() - fpp) / max(1, len(pool) - yy.sum())
        report["mixed_sweep"][str(ratio)] = {"attack_recall": round(r_, 4), "benign_precision": round(bprec, 4)}

    out = os.path.join(config.CACHE_DIR, "eval_report.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(json.dumps(report, indent=2))
    print(f"\n[eval] report -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
