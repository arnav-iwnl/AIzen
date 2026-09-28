"""Metrics helpers for AIzen v2 training/eval."""
import numpy as np


def binary_metrics(y_true, y_pred):
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "tp": tp, "tn": tn, "fp": fp, "fn": fn}


def accuracy(y_true, y_pred):
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    return round(float(np.mean(y_true == y_pred)), 4) if y_true.size else 0.0


def _thresholds(meta):
    """Per-class attack thresholds, mirroring the Node runtime exactly.

    v2/runtime/onnx_classifier.js:120-121 uses
    `attackThresholds[attackType] ?? this.threshold`. Scoring val with a bare
    argmax instead (the old behaviour) meant best.pt was selected by a decision
    rule the runtime never applies, so the val F1 could not detect a model that
    only looks good below threshold.
    """
    per_class = dict(meta.get("attack_thresholds") or {})
    default = float(meta.get("attack_threshold", 0.5))
    return per_class, default


def evaluate_model(model, loader, meta, device, per_class_thresholds=True):
    """Return {attack: binary_metrics, category: acc, severity: acc}."""
    import torch
    import torch.nn.functional as F

    model.eval()
    none_idx = meta["attack_index"].get("none", 0)
    inv = {v: k for k, v in meta["attack_index"].items()}
    thresholds, default_threshold = _thresholds(meta)
    y_attack, y_attack_pred, y_cat, y_cat_pred, y_sev, y_sev_pred = [], [], [], [], [], []
    with torch.no_grad():
        for ids, a, c, s in loader:
            ids = ids.to(device)
            logits = model(ids)
            probs = F.softmax(logits["attack"], dim=-1)
            conf, at = probs.max(-1)
            ct = logits["category"].argmax(-1)
            st = logits["severity"].argmax(-1)
            at_c, conf_c = at.cpu().numpy(), conf.cpu().numpy()
            y_attack.extend((a.numpy() != none_idx).astype(int).tolist())
            if per_class_thresholds:
                y_attack_pred.extend([
                    int(idx != none_idx and c >= thresholds.get(inv.get(int(idx), ""), default_threshold))
                    for idx, c in zip(at_c, conf_c)
                ])
            else:
                y_attack_pred.extend((at_c != none_idx).astype(int).tolist())
            y_cat.extend(c.numpy().tolist())
            y_cat_pred.extend(ct.cpu().numpy().tolist())
            y_sev.extend(s.numpy().tolist())
            y_sev_pred.extend(st.cpu().numpy().tolist())
    return {
        "attack": binary_metrics(y_attack, y_attack_pred),
        "category_acc": accuracy(y_cat, y_cat_pred),
        "severity_acc": accuracy(y_sev, y_sev_pred),
    }


def per_class_recall(model, loader, meta, device, per_class_thresholds=True):
    """Recall per attack class, using the same decision rule as the runtime."""
    import torch
    import torch.nn.functional as F

    model.eval()
    inv = {v: k for k, v in meta["attack_index"].items()}
    thresholds, default_threshold = _thresholds(meta)
    tp, total = {}, {}
    with torch.no_grad():
        for ids, a, c, s in loader:
            logits = model(ids.to(device))
            probs = F.softmax(logits["attack"], dim=-1)
            conf, at = probs.max(-1)
            pred, conf_c = at.cpu().numpy(), conf.cpu().numpy()
            true = a.numpy()
            for t, p, cf in zip(true, pred, conf_c):
                name = inv.get(int(t), "?")
                total[name] = total.get(name, 0) + 1
                hit = int(p == t and (int(t) == meta["attack_index"].get("none", 0)
                                       or cf >= thresholds.get(name, default_threshold)))
                tp[name] = tp.get(name, 0) + hit
    return {k: {"n": total[k], "recall": round(tp[k] / total[k], 4) if total[k] else 0.0}
            for k in sorted(total)}
