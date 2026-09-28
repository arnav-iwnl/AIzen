"""Train the AIzen v2 deep sequence model (LSTM/Transformer) on local GPU.

Run: python -m train.train_deep        (from v2/)
Requires: torch, numpy, scikit-learn (see requirements.txt), and a built
dataset (python -m prep.build_dataset).
"""
import json
import os
import sys
import time

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

import config
from train.models import build_model
from train.metrics import evaluate_model, per_class_recall


def _loss_weights(meta, device):
    w = meta.get("attack_weights") or {}
    if not w:
        return None
    vec = [w.get(k, 1.0) for k in sorted(meta["attack_index"], key=meta["attack_index"].get)]
    return torch.tensor(vec, dtype=torch.float, device=device)


def train():
    config.ensure_dirs()
    device = config.get_device()
    print(f"[train] device={device} model={config.MODEL}")

    from prep.dataset import build_datasets, make_loaders
    ballot = os.environ.get("V2_BALLOT_PATH")
    exp_dir = os.environ.get("V2_EXP_DIR") or config.CACHE_DIR
    os.makedirs(exp_dir, exist_ok=True)
    train_ds, val_ds, meta = build_datasets(syn=True, ballot_path=ballot)
    train_ld, val_ld = make_loaders(train_ds, val_ds)

    model = build_model(meta).to(device)
    print(f"[train] params={sum(p.numel() for p in model.parameters()):,} "
          f"attack_cls={len(meta['attack_index'])}")

    aw = _loss_weights(meta, device) if config.CLASS_BALANCE else None
    ce_attack = nn.CrossEntropyLoss(weight=aw)
    ce_cat = nn.CrossEntropyLoss()  # ponytail: per-head weights; only attack_weights exist
    ce_sev = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(model.parameters(), lr=config.LR, weight_decay=config.WEIGHT_DECAY)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=config.EPOCHS)

    best_f1 = -1
    best_state = None
    for epoch in range(1, config.EPOCHS + 1):
        model.train()
        total_loss, n_batch = 0.0, 0
        t0 = time.time()
        for ids, a, c, s in train_ld:
            ids, a, c, s = ids.to(device), a.to(device), c.to(device), s.to(device)
            logits = model(ids)
            loss = (ce_attack(logits["attack"], a) + ce_cat(logits["category"], c) + ce_sev(logits["severity"], s)) / 3
            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += loss.item()
            n_batch += 1
        scheduler.step()

        # `val_ld` is the CROSS-DOMAIN holdout (a dump the model never trained
        # on), scored with the runtime's per-class thresholds. This is the
        # number that matters; the old random-row split could not see a
        # cross-domain regression at all.
        res = evaluate_model(model, val_ld, meta, device)
        f1 = res["attack"]["f1"]
        print(f"[train] epoch {epoch:2d} loss={total_loss/max(n_batch,1):.4f} "
              f"holdout(P/R/F1)={res['attack']['precision']}/{res['attack']['recall']}/{f1} "
              f"cat_acc={res['category_acc']} sev_acc={res['severity_acc']} ({time.time()-t0:.1f}s)")
        if epoch == 1 or epoch % 2 == 0 or epoch == config.EPOCHS:
            per = per_class_recall(model, val_ld, meta, device)
            worst = sorted(per.items(), key=lambda kv: kv[1]["recall"])[:6]
            print("[train]   holdout per-class recall: " +
                  " ".join(f"{c}={v['recall']:.2f}(n={v['n']})" for c, v in worst))
        if f1 > best_f1:
            best_f1 = f1
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        ckpt = os.path.join(exp_dir, "best.pt")
        torch.save({"state_dict": best_state, "meta": meta, "attack_f1": best_f1}, ckpt)
        print(f"[train] best val attack F1={best_f1:.4f} saved -> {ckpt}")

    report = os.path.join(exp_dir, "train_report.json")
    with open(report, "w", encoding="utf-8") as fh:
        json.dump({"device": device, "best_attack_f1": best_f1, "meta_count": len(meta["attack_index"])}, fh, indent=2)
    print(f"[train] report -> {report}")
    return 0


if __name__ == "__main__":
    sys.exit(train())
