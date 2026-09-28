"""SIEM/OSSEC/Wazuh-focused evaluation of a trained checkpoint.

Scores a checkpoint on the OSSEC/Wazuh ingest records (data/ingest/*.jsonl)
using the checkpoint's OWN meta (label indices) and tokenizer. Reports binary
attack metrics + per-class F1 + confusion matrix + macro F1.

Run: python -m train.eval_siem --ckpt <path> [--out <json>]
"""
import argparse
import json
import os
import sys

import numpy as np
import torch
from torch.utils.data import TensorDataset, DataLoader

import config
from prep.tokenizer import CharTokenizer
from train.models import build_model


def _load_rows():
    import glob
    rows = []
    for p in sorted(glob.glob(os.path.join(config.CACHE_DIR, "ingest", "*.jsonl"))):
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    return rows


def _tensorize(rows, meta):
    """Attack labels are the SAME 7 classes in every experiment, so attack is
    always fully evaluated. Category/severity evaluated on rows whose labels
    exist in this checkpoint's maps (reported with per-head n)."""
    tok = CharTokenizer()
    attack_idx = meta["attack_index"]
    cat_idx = meta["category_index"]
    sev_idx = meta["severity_index"]
    ids, attack, cat, sev, cat_ok, sev_ok = [], [], [], [], [], []
    dropped = {"category": [], "severity": []}
    for r in rows:
        msg = (r.get("message") or "").strip()
        if not msg:
            continue
        at = r.get("attack_type") or "none"
        at = at if at in config.ATTACK_TYPES else ("other" if r.get("is_attack") else "none")
        if at not in attack_idx:
            continue  # class-map mismatch only (shouldn't happen, all share taxonomy)
        ids.append(tok.encode(msg))
        attack.append(attack_idx[at])
        catv = r.get("category") or "Unknown"
        if catv in cat_idx:
            cat.append(cat_idx[catv])
            cat_ok.append(True)
        else:
            cat.append(0)
            cat_ok.append(False)
            dropped["category"].append(catv)
        sevv = r.get("severity") or "medium"
        if sevv in sev_idx:
            sev.append(sev_idx[sevv])
            sev_ok.append(True)
        else:
            sev.append(0)
            sev_ok.append(False)
            dropped["severity"].append(sevv)
    if not ids:
        return None, dropped, None, None
    return (TensorDataset(torch.tensor(ids, dtype=torch.long),
                          torch.tensor(attack, dtype=torch.long),
                          torch.tensor(cat, dtype=torch.long),
                          torch.tensor(sev, dtype=torch.long)),
            dropped, np.asarray(cat_ok, dtype=bool), np.asarray(sev_ok, dtype=bool))


def _per_class(y_true, y_pred, index, reversed_map):
    """confusion matrix (n_classes x n_classes) + per-class prec/rec/f1."""
    n = len(index)
    conf = np.zeros((n, n), dtype=int)
    for t, p in zip(y_true, y_pred):
        conf[t][p] += 1
    per = {}
    for name, i in index.items():
        tp = conf[i][i]
        fp = conf[:, i].sum() - tp
        fn = conf[i].sum() - tp
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        per[name] = {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4), "n": int(conf[i].sum())}
    return conf.tolist(), per


def evaluate(ckpt_path, out_path=None):
    device = config.get_device()
    ckpt = torch.load(ckpt_path, map_location=device)
    meta = ckpt["meta"]
    model = build_model(meta).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    rows = _load_rows()
    ds, dropped, cat_ok, sev_ok = _tensorize(rows, meta)
    if ds is None:
        print("[eval_siem] no labeled SIEM rows")
        return 1
    loader = DataLoader(ds, batch_size=256, shuffle=False)

    y_attack, y_attack_pred, y_attack_cls, y_attack_cls_pred, y_cat, y_cat_pred, y_sev, y_sev_pred = [], [], [], [], [], [], [], []
    none_idx = meta["attack_index"].get("none", 0)
    with torch.no_grad():
        for ids, a, c, s in loader:
            ids = ids.to(device)
            logits = model(ids)
            a = a.numpy()
            at_pred = logits["attack"].argmax(-1).cpu().numpy()
            y_attack_cls.extend(a.tolist())
            y_attack_cls_pred.extend(at_pred.tolist())
            y_attack.extend((a != none_idx).astype(int).tolist())
            y_attack_pred.extend((at_pred != none_idx).astype(int).tolist())
            y_cat.extend(c.numpy().tolist())
            y_cat_pred.extend(logits["category"].argmax(-1).cpu().numpy().tolist())
            y_sev.extend(s.numpy().tolist())
            y_sev_pred.extend(logits["severity"].argmax(-1).cpu().numpy().tolist())

    def _bm(y, p):
        tp = sum(1 for t, q in zip(y, p) if t == 1 and q == 1)
        tn = sum(1 for t, q in zip(y, p) if t == 0 and q == 0)
        fp = sum(1 for t, q in zip(y, p) if t == 0 and q == 1)
        fn = sum(1 for t, q in zip(y, p) if t == 1 and q == 0)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        return {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                "tp": tp, "tn": tn, "fp": fp, "fn": fn}

    attack = _bm(y_attack, y_attack_pred)
    conf_attack, per_class = _per_class(y_attack_cls, y_attack_cls_pred, meta["attack_index"], None)
    macro_f1 = float(np.mean([v["f1"] for v in per_class.values()])) if per_class else 0.0

    y_attack = np.asarray(y_attack)
    y_cat = np.asarray(y_cat)
    y_sev = np.asarray(y_sev)
    cat_acc = round(float(np.mean((y_cat == y_cat_pred)[cat_ok])), 4) if cat_ok.any() else 0.0
    sev_acc = round(float(np.mean((y_sev == y_sev_pred)[sev_ok])), 4) if sev_ok.any() else 0.0

    report = {
        "checkpoint": ckpt_path,
        "n": len(y_attack),
        "attack_binary": attack,
        "macro_f1": round(macro_f1, 4),
        "per_class_attack": per_class,
        "attack_confusion": conf_attack,
        "category_acc": cat_acc,
        "severity_acc": sev_acc,
        "dropped_labels": dropped,
    }
    print(json.dumps(report, indent=2))
    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[eval_siem] report -> {out_path}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    sys.exit(evaluate(args.ckpt, args.out))