"""Builds the torch Dataset and label/index artifacts from the ballot.

Produces:
  - data/labels.json  (attack_type / category / severity -> index)
  - data/train.pt / val.pt  (tensors of ids + one-hot-assignable labels)
"""
import json
import math
import os
import random

import torch
from torch.utils.data import TensorDataset, DataLoader

import config
from ingest.normalize import fingerprint as _fingerprint  # single canonical key
from prep.tokenizer import CharTokenizer, save_tokenizer

# how many rows to load when ballot is astronomically large (dev ceiling)
MAX_ROWS = int(os.environ.get("V2_MAX_ROWS", 0)) or None


def _squeeze(seqs, max_len):
    return [s[:max_len] for s in seqs]


def _split_key(row):
    """Group key for leakage-free splits: same source IP traffic stays together.

    Fall back to (sequence fingerprint) when no identity field exists so
    identical messages never straddle the split either.
    """
    ip = row.get("src_ip")
    if ip:
        return f"ip:{ip}"
    host = row.get("host")
    if host:
        return f"host:{host}"
    return f"fp:{row.get('__fp', id(row))}"


def build_datasets(syn=False, ballot_path=None, val_ratio=0.2, group_split=True, seed=0,
                   holdout=True):
    """Return (train_ds, val_ds, meta) where meta holds label maps + weight.

    `holdout=True` (default) partitions by SOURCE DOMAIN using
    `config.HOLDOUT_DATASETS`: those rows never enter training and become the
    validation set, so val measures generalization to a dump the model has not
    seen. The label index is built from TRAIN ROWS ONLY — otherwise a class that
    exists solely in the holdout would occupy an output slot the model never
    learned, and the holdout row would score against a random weight.

    `group_split` (used when holdout is off) splits by src_ip/host so a single
    attacker's events never straddle the boundary.
    """
    ballot_path = ballot_path or (config.TRAIN_BALLOT.replace(".jsonl", ".synth.jsonl") if syn else config.TRAIN_BALLOT)
    tok = CharTokenizer()

    attack_idx = {}
    cat_idx = {}
    sev_idx = {}
    sequences, attack_labels, cat_labels, sev_labels = [], [], [], []
    row_attack_type = []
    attack_counts = {}

    rows = []
    with open(ballot_path, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if MAX_ROWS and i >= MAX_ROWS:
                break
            rows.append(json.loads(line))

    # ── pass 1: which rows are holdout ────────────────────────────────────
    # Two mechanisms, deliberately:
    #   HOLDOUT_EXCLUDE  - the dataset never trains at all (unseen-format probe)
    #   HOLDOUT_FRACTION - a per-dataset slice, so the model still learns the
    #                      format while still being scored on lines it never saw
    use_holdout = bool(holdout and (config.HOLDOUT_EXCLUDE or config.HOLDOUT_FRACTION > 0))
    by_dataset = {}
    for r in rows:
        by_dataset.setdefault(r.get("dataset") or "", []).append(r)

    # Deterministically pick the holdout slice per dataset (stable across runs).
    holdout_pick = set()
    for ds, drows in by_dataset.items():
        if ds in config.HOLDOUT_EXCLUDE:
            holdout_pick.update(id(r) for r in drows)
            continue
        n = int(len(drows) * config.HOLDOUT_FRACTION)
        for r in drows[:n]:
            holdout_pick.add(id(r))

    is_holdout = [id(r) in holdout_pick for r in rows]

    train_rows_idx = [i for i in range(len(rows)) if not is_holdout[i]]

    # ── pass 2: count labels over TRAIN rows, demote too-rare attack classes,
    # then build the index from the survivors only ────────────────────────
    def _label(r):
        at = r.get("attack_type") or "none"
        at = at if config.is_valid_attack_type(at) else ("other" if r.get("is_attack") else "none")
        cat = r.get("category") or "Unknown"
        if cat not in config.CATEGORIES:
            cat = "Unknown"
        sev = r.get("severity") or "info"
        if sev not in config.SEVERITIES:
            sev = "medium"
        return at, cat, sev

    train_labels = {i: _label(rows[i]) for i in train_rows_idx}
    train_counts = {}
    for at, _c, _s in train_labels.values():
        train_counts[at] = train_counts.get(at, 0) + 1

    # A class with only a few dozen examples cannot be learned by a 615k-param
    # model; it just becomes confident noise (the shipped model scored 0% recall
    # on `scanner`, which had 76 rows and needed a 139x loss weight). Demote
    # anything under the floor to `other` so it stops occupying an output slot.
    min_rows = int(os.environ.get("V2_MIN_CLASS_ROWS", "200"))
    demoted = {c: n for c, n in train_counts.items() if c != "none" and n < min_rows}

    def _label_final(r):
        at, cat, sev = _label(r)
        if at in demoted:
            at = "other"
        return at, cat, sev

    for at, _c, _s in train_labels.values():
        at = "other" if at in demoted else at
        if at not in attack_idx:
            attack_idx[at] = len(attack_idx)
    for i in train_rows_idx:
        _a, cat, sev = _label_final(rows[i])
        if cat not in cat_idx:
            cat_idx[cat] = len(cat_idx)
        if sev not in sev_idx:
            sev_idx[sev] = len(sev_idx)
    attack_counts = {c: n for c, n in train_counts.items() if c not in demoted}

    # ── pass 3: tensorize; rows whose class exists only in the holdout are
    # mapped to a train-known fallback (or skipped) rather than crashing ────
    holdout_skipped = 0
    orig_of = []          # tensor index -> original row index
    cat_fallback = cat_idx.get("Unknown", 0)
    sev_fallback = sev_idx.get("medium", 0)
    for i, r in enumerate(rows):
        msg = (r.get("message") or "").strip()
        if not msg:
            continue
        at, cat, sev = _label_final(r)
        if at not in attack_idx:      # attack class exists only in the holdout
            holdout_skipped += 1
            continue
        r["__fp"] = _fingerprint(msg)
        # The model reads the LOG PAYLOAD, not the SIEM alert envelope. `message`
        # is prefix-wrapped by the SIEM ("<alert desc> <body>"), and training on
        # that teaches the network to read the wrapper — which is how a benign
        # Cisco switch syslog ended up scored as `bruteforce`. Rows without a
        # payload (web access logs, plain corpora) are already bare text.
        text = (r.get("payload") or "").strip() or msg
        sequences.append(tok.encode(text))
        attack_labels.append(attack_idx[at])
        cat_labels.append(cat_idx.get(cat, cat_fallback))
        sev_labels.append(sev_idx.get(sev, sev_fallback))
        row_attack_type.append(at)
        orig_of.append(i)

    rng = random.Random(seed)
    idxs = list(range(len(sequences)))

    if use_holdout:
        train_idxs = [k for k, orig in enumerate(orig_of) if not is_holdout[orig]]
        val_idxs = [k for k, orig in enumerate(orig_of) if is_holdout[orig]]
        rng.shuffle(train_idxs)
    elif group_split:
        # Shuffle groups (ip/host), then assign whole groups to train/val.
        order = rng.sample(idxs, len(idxs))
        groups = {}
        for i in order:
            key = _split_key(rows[i])
            groups.setdefault(key, []).append(i)
        group_ids = list(groups.keys())
        rng.shuffle(group_ids)
        k = int(len(group_ids) * (1 - val_ratio))
        train_set = set()
        for g in group_ids[:k]:
            train_set.update(groups[g])
        train_idxs = sorted(train_set)
        val_idxs = [i for i in idxs if i not in train_set]
        rng.shuffle(train_idxs)
        rng.shuffle(val_idxs)
    else:
        rng.shuffle(idxs)
        k = int(len(idxs) * (1 - val_ratio))
        train_idxs, val_idxs = idxs[:k], idxs[k:]

    def _t(seq, a, c, s):
        return (
            torch.tensor(seq, dtype=torch.long),
            torch.tensor(a, dtype=torch.long),
            torch.tensor(c, dtype=torch.long),
            torch.tensor(s, dtype=torch.long),
        )

    train = TensorDataset(*_t(
        [sequences[i] for i in train_idxs],
        [attack_labels[i] for i in train_idxs],
        [cat_labels[i] for i in train_idxs],
        [sev_labels[i] for i in train_idxs],
    ))
    val = TensorDataset(*_t(
        [sequences[i] for i in val_idxs],
        [attack_labels[i] for i in val_idxs],
        [cat_labels[i] for i in val_idxs],
        [sev_labels[i] for i in val_idxs],
    ))

    # inverse class weights for attack head (rare types upweighted)
    n_attack = len(attack_labels)
    weights = {}
    if config.CLASS_BALANCE:
        n_classes = len(attack_idx)
        total = n_attack
        for k in attack_idx:
            c = attack_counts.get(k, 0)
            weights[k] = total / (n_classes * (c + 1)) if total else 1.0

    meta = {
        "attack_index": attack_idx,
        "category_index": cat_idx,
        "severity_index": sev_idx,
        "attack_weights": weights,
        "train_size": len(train),
        "val_size": len(val),
        # Cross-domain bookkeeping — the val set is a held-out DUMP, not a
        # random slice of the training distribution.
        "holdout_mode": bool(use_holdout),
        "holdout_datasets_excluded": sorted(config.HOLDOUT_EXCLUDE) if use_holdout else [],
        "holdout_fraction": config.HOLDOUT_FRACTION if use_holdout else 0.0,
        "holdout_rows_skipped_unseen_class": holdout_skipped,
        "min_class_rows": min_rows,
        "demoted_classes": demoted,
        "val_class_counts": {c: sum(1 for i in val_idxs if row_attack_type[i] == c)
                             for c in attack_idx},
    }
    # Carry the RUNTIME thresholds into the training meta so val is scored with
    # the same decision rule the Node runtime applies. Without this the training
    # meta has no thresholds at all and falls back to 0.5, which is far more
    # permissive than the 0.85-0.94 actually in force.
    try:
        with open(os.path.join(config.RUNTIME_DIR, "meta.json"), encoding="utf-8") as fh:
            runtime_meta = json.load(fh)
        if runtime_meta.get("attack_thresholds"):
            meta["attack_thresholds"] = runtime_meta["attack_thresholds"]
        if runtime_meta.get("attack_threshold") is not None:
            meta["attack_threshold"] = runtime_meta["attack_threshold"]
    except (OSError, ValueError):
        pass

    os.makedirs(config.CACHE_DIR, exist_ok=True)
    with open(os.path.join(config.CACHE_DIR, "labels.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    save_tokenizer()
    return train, val, meta


def make_loaders(train_ds, val_ds, batch_size=config.BATCH_SIZE):
    train_ld = DataLoader(train_ds, batch_size=batch_size, shuffle=True, drop_last=True, num_workers=0)
    val_ld = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=0)
    return train_ld, val_ld
