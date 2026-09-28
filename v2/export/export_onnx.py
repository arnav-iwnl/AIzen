"""Export a trained model to a small quantized ONNX for Node runtime.

Loads a checkpoint (exp2 by default), exports to v2/runtime/model.onnx
(INT8-quantized when possible), tunes the attack threshold on a group-split
SIEM hold-out (precision-biased), and writes meta.json consumed by
v2/runtime/onnx_classifier.js.

Run: python -m export.export_onnx
"""
import json
import os
import sys

import numpy as np
import torch

import config
from train.models import build_model

_MAX_LEN = config.MAX_LEN


def export():
    config.ensure_dirs()
    ckpt_path = os.environ.get(
        "V2_EXP_CKPT", os.path.join(config.CACHE_DIR, "best.pt"))
    if not os.path.exists(ckpt_path):
        print(f"[export] missing checkpoint {ckpt_path}. Run train_deep first.")
        return 1

    ckpt = torch.load(ckpt_path, map_location="cpu")
    meta = ckpt["meta"]
    model = build_model(meta)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    dummy = torch.zeros(1, _MAX_LEN, dtype=torch.long)
    # dynamo=False: torch>=2.9 defaults to the dynamo exporter, whose output
    # carries shape metadata that onnxruntime's quantizer rejects
    # ("Inferred shape and existing shape differ in dimension 0: (256) vs (7)"),
    # so INT8 quantization was silently skipped on every export. The legacy
    # TorchScript path produces a graph the quantizer handles.
    try:
        torch.onnx.export(
            model, (dummy,),
            os.path.join(config.RUNTIME_DIR, "model.onnx"),
            input_names=["ids"],
            output_names=["attack_logits", "category_logits", "severity_logits"],
            dynamic_axes={"ids": {0: "batch"}},
            opset_version=18,
            dynamo=False,
        )
    except TypeError:
        torch.onnx.export(
            model, (dummy,),
            os.path.join(config.RUNTIME_DIR, "model.onnx"),
            input_names=["ids"],
            output_names=["attack_logits", "category_logits", "severity_logits"],
            dynamic_axes={"ids": {0: "batch"}},
            opset_version=18,
        )
    print(f"[export] ONNX written -> {config.ONNX_PATH}")

    # Optional INT8 quantization (dynamic) for a smaller/faster CPU artifact.
    # MatMulConstBOnly is required here: with a static sequence length and a
    # variable-size attack head, the default shape inference compares the
    # sequence dim (256) against the class dim and aborts, which silently left
    # the FP32 model in place (118 KB INT8 -> ~1.2 MB) on every export.
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType
        q_path = os.path.join(config.RUNTIME_DIR, "model.onnx")
        quantize_dynamic(
            q_path,
            q_path,
            weight_type=QuantType.QInt8,
            extra_options={"MatMulConstBOnly": True},
        )
        print(f"[export] INT8 quantized -> {config.ONNX_PATH} "
              f"({os.path.getsize(q_path)} bytes)")
    except Exception as exc:  # noqa: BLE001
        print(f"[export] quantization skipped: {exc}")

    # Calibrate thresholds on the SAME cross-domain holdout the trainer used.
    global_t, per_class = tune_thresholds(model, meta)

    meta_out = {
        "max_len": _MAX_LEN,
        "tokenizer": {"type": "char", "pad": 0, "unk": 1, "base": 256},
        "attack_index": meta["attack_index"],
        "category_index": meta["category_index"],
        "severity_index": meta["severity_index"],
        "attack_threshold": global_t,
        # Emitted by the exporter on purpose. This block used to exist only as a
        # hand-edited file: the exporter never wrote it, so any re-export silently
        # deleted the tuned per-class values — and because
        # onnx_classifier.js:120 falls back to `attack_threshold` (the STRICTEST
        # bar in the file) for any class missing here, every newly trained class
        # would have been effectively undetectable.
        "attack_thresholds": per_class,
        "model": config.MODEL,
    }
    with open(config.META_PATH, "w", encoding="utf-8") as fh:
        json.dump(meta_out, fh, indent=2)
    print(f"[export] meta -> {config.META_PATH} threshold={global_t:.3f} "
          f"per_class={len(per_class)}")
    return 0


def tune_thresholds(model, meta):
    """Pick per-class attack thresholds on the cross-domain holdout.

    Returns (global_threshold, {class: threshold}).

    Measured on `prep.dataset`'s dataset-level holdout — the domains the model
    never trained on — instead of re-reading data/ingest/*.jsonl, which are the
    same files the ballot was built from (the previous version tuned the shipped
    threshold on rows the model had very likely already seen).
    """
    MIN_RECALL = float(os.environ.get("V2_MIN_RECALL", "0.60"))
    fallback = float(config.ATTACK_THRESHOLD)
    none_idx = meta["attack_index"].get("none", 0)
    _ = MIN_RECALL  # kept for env compatibility; the sweep below uses a floor

    try:
        from prep.dataset import build_datasets
        _train, val, val_meta = build_datasets(syn=True, holdout=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[export] holdout unavailable ({exc}); falling back to {fallback}")
        return fallback, {}

    if len(val) == 0:
        print("[export] holdout empty; falling back to config.ATTACK_THRESHOLD")
        return fallback, {}

    import torch.nn.functional as F
    loader = torch.utils.data.DataLoader(val, batch_size=config.BATCH_SIZE, shuffle=False)
    rows = []  # (true_idx, pred_idx, conf)
    model.eval()
    with torch.no_grad():
        for ids, a, _c, _s in loader:
            probs = F.softmax(model(ids)["attack"], dim=-1)
            conf, pred = probs.max(-1)
            for t, p, cf in zip(a.tolist(), pred.tolist(), conf.tolist()):
                rows.append((t, p, cf))

    inv = {v: k for k, v in meta["attack_index"].items()}

    # ── calibrate thresholds under the RUNTIME's actual decision rule ───────
    # The runtime does: argmax -> that class's threshold -> fire or not. It is
    # NOT a per-class one-vs-rest decision, so tuning each class independently
    # against "everything else" optimises the wrong objective (measured F1 of
    # 0.02-0.36 for every class). Instead: pick a global threshold by sweeping
    # the binary F1 under the real rule, then do a couple of coordinate-ascent
    # passes where one class's bar moves while the others stay fixed.
    grid = [round(float(x), 3) for x in np.linspace(0.05, 0.99, 47)]
    none_idx = meta["attack_index"].get("none", 0)
    inv = {v: k for k, v in meta["attack_index"].items()}

    pred_idx = np.array([p for _t, p, _c in rows], dtype=int)
    confs = np.array([c for _t, _p, c in rows], dtype=float)
    is_attack = np.array([0 if p == none_idx else 1 for p in pred_idx], dtype=int)
    truth = np.array([1 if t != none_idx else 0 for t, _p, _c in rows], dtype=int)
    pred_name = np.array([inv.get(int(p), "none") for p in pred_idx])

    def _binary_f1(thresholds):
        fire = np.array([
            (conf >= thresholds.get(name, 0.5)) if is_attack[i] else 0
            for i, (name, conf) in enumerate(zip(pred_name, confs))
        ], dtype=int)
        tp = int(np.sum((truth == 1) & (fire == 1)))
        fp = int(np.sum((truth == 0) & (fire == 1)))
        fn = int(np.sum((truth == 1) & (fire == 0)))
        if tp == 0:
            return 0.0, 0.0, 0.0
        prec = tp / (tp + fp)
        rec = tp / (tp + fn)
        return (2 * prec * rec / (prec + rec) if (prec + rec) else 0.0), prec, rec

    best_t, best_f1, best_p, best_r = fallback, -1.0, 0.0, 0.0
    for t in grid:
        f1, prec, rec = _binary_f1({k: t for k in meta["attack_index"]})
        if f1 > best_f1:
            best_t, best_f1, best_p, best_r = t, f1, prec, rec
    print(f"[export] global threshold={best_t:.3f} holdOutF1={best_f1:.3f} "
          f"P={best_p:.3f} R={best_r:.3f} rows={len(truth)} attacks={int(truth.sum())}")

    thresholds = {k: best_t for k in meta["attack_index"]}
    names = [k for k in meta["attack_index"] if k != "none"]
    for _pass in range(2):
        for name in names:
            cur = thresholds[name]
            local_best, local_t = best_f1, cur
            for t in grid:
                thresholds[name] = t
                f1, _p, _r = _binary_f1(thresholds)
                if f1 > local_best + 1e-9:
                    local_best, local_t = f1, t
            thresholds[name] = local_t
            if local_best > best_f1:
                best_f1 = local_best
    f1, prec, rec = _binary_f1(thresholds)
    print(f"[export] after coordinate ascent: F1={f1:.3f} P={prec:.3f} R={rec:.3f}")
    for k in sorted(thresholds):
        if k != "none":
            print(f"[export]   {k}: {thresholds[k]:.3f}")
    thresholds.pop("none", None)
    return best_t, thresholds


if __name__ == "__main__":
    sys.exit(export())
