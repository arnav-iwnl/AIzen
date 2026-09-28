"""Pull Wazuh/OSSEC alert corpora from Hugging Face into labeled v2 records.

Sources (verified live):
  - yonatane22-bh/sereniq-wazuh-alerts   10k raw Wazuh alerts w/ rule metadata,
    MITRE mapping, triage labels (should_escalate / triage_label).
  - kholil-lil/wazuh-alerts + ruf0x/wazuh-alerts  738+738 instruction pairs that
    classify each alert JSON as True/False Positive.

Labels come from the dataset's OWN annotations:
  - sereniq: attacker if should_escalate or triage_label==ESCALATE or known bad
    IP; subtype coarse-mapped from MITRE tactic when no payload signature.
  - TP/FP sets: is_attack = (output == "True Positive"); subtype from rule
    description heuristic, else "other".
Rule id/level/groups/source kept as provenance on every row.

Run: python -m ingest.wazuh_ingest   (requires `datasets` + network)
"""
import json
import os
import sys

import config
from ingest.common import mkdir


def _write(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(rows)


def _sev(level):
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "medium"
    if level >= 10:
        return "critical"
    if level >= 7:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


_MITRE_SUB = {
    "Reconnaissance": "scanner",
    "Discovery": "scanner",
    "Credential Access": "bruteforce",
    "Initial Access": "other",
    "Execution": "other",
    "Lateral Movement": "other",
    "Exfiltration": "other",
    "Ransomware": "other",
    "Command and Control": "other",
    "Defense Evasion": "other",
}


def _subtype(message, mitre=None, technique=None):
    """Attack label for a Wazuh alert.

    Prefer the payload signature (obfuscation-tolerant), then the source's own
    ATT&CK technique id, then the coarse tactic. Emitting the real technique id
    ("T1021", "T1486") instead of folding it into "other" is what lets the attack
    head learn a growing, data-driven label space — the runtime reads whatever
    classes it finds in meta.json, so no code change is needed to add one.
    """
    from ingest.normalize import heuristic_attack
    at = heuristic_attack(message)
    if at:
        return at
    if technique and str(technique).strip().upper().startswith("T"):
        return str(technique).strip().upper()
    if mitre:
        return _MITRE_SUB.get(mitre, "other")
    return "other"


# ── sereniq ──────────────────────────────────────────────────────────────
def _normalize_sereniq(rows):
    out = []
    for r in rows:
        desc = str(r.get("rule_description") or "").strip()
        summary = str(r.get("summary") or "").strip()
        msg = (f"{desc} | {summary}" if summary else desc)
        if not msg:
            continue
        # Same envelope/payload split as ossec_ingest: the model reads `payload`,
        # the UI and RCA read `message`.
        payload = summary or desc
        level = r.get("rule_level") or 0
        escalate = bool(r.get("should_escalate")) or (str(r.get("triage_label") or "").upper() == "ESCALATE")
        bad_ip = bool(r.get("is_known_bad_ip"))
        is_attack = escalate or bad_ip
        mitre = r.get("mitre_tactic") or None
        out.append({
            "message": msg[:512],
            "payload": payload[:512],
            "alert_desc": desc[:512],
            "is_attack": int(is_attack),
            "attack_type": _subtype(payload, mitre, r.get("mitre_technique")) if is_attack else "none",
            "category": "Security" if is_attack else "Unknown",
            "severity": _sev(level),
            "dataset": "sereniq-wazuh-alerts",
            "rule_id": str(r.get("rule_id") or "?"),
            "rule_level": level,
            "src_ip": r.get("src_ip"),
            "src_ip_type": r.get("src_ip_type"),
            "mitre_tactic": mitre,
            "mitre_technique": r.get("mitre_technique"),
            "triage_label": r.get("triage_label"),
            "agent": r.get("agent_name"),
            "agent_ip": r.get("agent_ip"),
            "asset": r.get("asset_name"),
            "raw": json.dumps(r, ensure_ascii=False),
        })
    return out


# ── TP/FP instruction sets ───────────────────────────────────────────────
def _normalize_tpfp(rows):
    out = []
    for r in rows:
        try:
            d = json.loads(r.get("input") or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        rule = d.get("rule") or {}
        desc = str(rule.get("description") or "").strip()
        level = rule.get("level") or 0
        full_log = str(d.get("full_log") or "").strip()
        groups = rule.get("groups") or []
        msg = (f"{desc} | {full_log}" if full_log else desc)[:512]
        if not msg:
            continue
        is_attack = str(r.get("output") or "").strip().lower().startswith("true")
        out.append({
            "message": msg,
            "is_attack": int(is_attack),
            "attack_type": _subtype(msg) if is_attack else "none",
            "category": "Security" if is_attack else "Unknown",
            "severity": _sev(level),
            "dataset": "wazuh-tpfp",
            "rule_id": str(rule.get("id") or "?"),
            "rule_level": level,
            "groups": groups,
            "src_ip": (d.get("data") or {}).get("srcip") if isinstance(d.get("data"), dict) else None,
            "agent": (d.get("agent") or {}).get("name") if isinstance(d.get("agent"), dict) else None,
            "raw": r.get("input"),
        })
    return out


def main():
    config.ensure_dirs()
    outdir = mkdir(os.path.join(config.CACHE_DIR, "ingest"))
    try:
        import datasets as ds
    except Exception as exc:  # noqa: BLE001
        print(f"[wazuh] 'datasets' not importable ({exc}); skipping HF sources.")
        return

    pulled = 0
    try:
        data = ds.load_dataset("yonatane22-bh/sereniq-wazuh-alerts", split="train")
        n = _write(os.path.join(outdir, "wazuh_sereniq.jsonl"),
                   _normalize_sereniq(list(data)))
        print(f"[wazuh] sereniq: {n} records")
        pulled += n
    except Exception as exc:  # noqa: BLE001
        print(f"[wazuh] sereniq failed: {exc}")

    for hfid in ("kholil-lil/wazuh-alerts", "ruf0x/wazuh-alerts"):
        try:
            data = ds.load_dataset(hfid, split="train")
            name = hfid.split("/")[-1]
            n = _write(os.path.join(outdir, f"wazuh_{name}.jsonl"),
                       _normalize_tpfp(list(data)))
            print(f"[wazuh] {name}: {n} records")
            pulled += n
        except Exception as exc:  # noqa: BLE001
            print(f"[wazuh] {hfid} failed: {exc}")

    print(f"[wazuh] total records pulled: {pulled}")
    return 0


if __name__ == "__main__":
    sys.exit(main())