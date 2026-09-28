"""Run SIEM training experiments on the existing pipeline.

Experiments (configurable via --mix):
  exp1  existing corpus only                (baseline ballot, no OSSEC/Wazuh)
  exp2  existing + OSSEC/Wazuh local+HuggingFace
  exp3  existing + OSSEC/Wazuh + extra log corpus   (benign realism)
  exp4  existing + OSSEC/Wazuh + logs + IDS public sets

Each experiment:
  - builds a ballot jsonl from the merged source rows (toggled by mix)
  - trains a fresh model into experiments/<name>/best.pt  (original best.pt
    in experiments/baseline/ is NEVER overwritten)
  - evaluates on a group-safe val split + a SIEM/OSSEC-specific eval
  - writes dataset/training/evaluation reports to reports/

Run: python -m experiments.run --mix exp1
"""
import argparse
import json
import os
import subprocess
import sys

import config


EXPERIMENTS = {
    "exp1": {"datasets": ["legacy"]},
    "exp2": {"datasets": ["legacy", "siem"]},
    "exp3": {"datasets": ["legacy", "siem", "logs"]},
    "exp4": {"datasets": ["legacy", "siem", "logs", "ids"]},
}


def _load_ingests():
    rows = {}
    for folder in ("siem", "logs", "ids"):
        rows[folder] = {}
    import glob
    # siem: tagged ossec/wazuh records
    for p in glob.glob(os.path.join(config.CACHE_DIR, "ingest", "*.jsonl")):
        src = os.path.basename(p).replace(".jsonl", "")
        with open(p, encoding="utf-8") as fh:
            rows["siem"][src] = [json.loads(l) for l in fh if l.strip()]
    return rows


def build_ballot(mix, out_path):
    """Write an experiment ballot with a 'source' tag per row."""
    from ingest.normalize import (  # reuse the tagged normalizers
        _normalize_plain_logs, _normalize_kaggle_csv, _normalize_hf_jsonl,
        _merge_rows,
    )
    want = EXPERIMENTS[mix]["datasets"]
    sources = []
    if "legacy" in want:
        sources += [
            ("plain-log", _normalize_plain_logs()),
            ("kaggle-csv", _normalize_kaggle_csv()),
            ("hf-web", _normalize_hf_jsonl()),
        ]
    if "siem" in want or "logs" in want or "ids" in want:
        ingests = _load_ingests()
        local = []
        if "siem" in want:
            for src_rows in ingests["siem"].values():
                local += src_rows
        if "logs" in want:
            local += ingests["logs"].get("loghub", [])
        if "ids" in want:
            local += ingests["ids"].get("ids", [])
        if local:
            sources.append(("local", local))

    merged = _merge_rows(sources)
    with open(out_path, "w", encoding="utf-8") as fh:
        for r in merged:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    attack = sum(1 for r in merged if r["is_attack"])
    print(f"[run:{mix}] ballot rows={len(merged)} attack={attack} benign={len(merged)-attack}")
    return merged


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mix", default="exp2")
    ap.add_argument("--skip-train", action="store_true")
    args = ap.parse_args()
    name = args.mix
    if name not in EXPERIMENTS:
        raise SystemExit(f"unknown mix {name}; choices={list(EXPERIMENTS)}")

    exp_dir = os.path.join(config.V2_ROOT, "experiments", name)
    os.makedirs(exp_dir, exist_ok=True)
    report_dir = os.path.join(config.V2_ROOT, "reports")
    os.makedirs(report_dir, exist_ok=True)

    ballot = os.path.join(exp_dir, "ballot.jsonl")
    merged = build_ballot(name, ballot)

    from collections import Counter
    dist = Counter(r["attack_type"] for r in merged)
    dataset_report = {
        "experiment": name,
        "sources": EXPERIMENTS[name]["datasets"],
        "n_rows": len(merged),
        "attack_type_distribution": dict(dist.most_common()),
        "by_source": dict(Counter(r.get("dataset", "?") for r in merged).most_common()),
        "provenance_fields": ["dataset", "rule_id", "rule_level", "src_ip", "host", "groups", "raw"],
    }
    with open(os.path.join(report_dir, f"dataset_report_{name}.json"), "w", encoding="utf-8") as fh:
        json.dump(dataset_report, fh, indent=2)

    if not args.skip_train:
        env = dict(os.environ)
        env["V2_BALLOT_PATH"] = ballot
        env["V2_EXP_DIR"] = exp_dir
        r = subprocess.run([sys.executable, "-m", "train.train_deep"], cwd=config.V2_ROOT, env=env)
        if r.returncode != 0:
            print(f"[run:{name}] WARN train_deep rc={r.returncode}; continuing to eval")

    ckpt = os.path.join(exp_dir, "best.pt")
    if not os.path.exists(ckpt):
        raise SystemExit(f"no checkpoint at {ckpt}")
    tr = os.path.join(exp_dir, "train_report.json")
    ev = os.path.join(report_dir, f"evaluation_report_{name}.json")
    r = subprocess.run([sys.executable, "-m", "train.eval_siem", "--ckpt", ckpt, "--out", ev],
                       cwd=config.V2_ROOT)
    if r.returncode != 0:
        raise SystemExit(f"eval failed for {name}")
    if os.path.exists(tr):
        with open(tr, encoding="utf-8") as fh:
            print(f"[run:{name}] {json.load(fh)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())