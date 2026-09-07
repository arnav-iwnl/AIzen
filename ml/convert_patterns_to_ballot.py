#!/usr/bin/env python3
"""
Convert existing `data/labeled/patterns.jsonl` into `v2/data/ballot.jsonl` for v2 training.

Heuristics:
- Use `message` as the text field, fallback to `raw`.
- Determine `attack_type` from `securityTypes` or `matchedRule`.
- `is_attack` = 1 when securityTypes present or matchedRule starts with "security:", else 0.

Produces: v2/data/ballot.jsonl (creates v2/data if needed) and prints a few sample lines.
"""
import json
import os
from pathlib import Path

SRC = Path("data/labeled/patterns.jsonl")
DST_DIR = Path("v2/data")
DST = DST_DIR / "ballot.jsonl"

TYPE_MAP = {
    "XSS_PROBE": "xss",
    "SQL_INJECTION": "sql-injection",
    "PATH_TRAVERSAL": "path-traversal",
    "ADMIN_BRUTE_FORCE": "bruteforce",
    "CREDENTIAL_PROBE": "bruteforce",
    "SCANNER_SIGNATURE": "scanner",
}

def normalize_attack_type(security_types, matched_rule):
    if security_types:
        for t in security_types:
            if t in TYPE_MAP:
                return TYPE_MAP[t]
        # fallback to lowercase of first type
        return security_types[0].lower()

    if isinstance(matched_rule, str) and matched_rule.startswith("security:"):
        token = matched_rule.split(":", 1)[1].strip().upper()
        return TYPE_MAP.get(token, token.lower())

    return "none"


def main():
    if not SRC.exists():
        print(f"Source file not found: {SRC}")
        return

    DST_DIR.mkdir(parents=True, exist_ok=True)

    out_count = 0
    samples = []
    with SRC.open("r", encoding="utf-8") as inf, DST.open("w", encoding="utf-8") as outf:
        for line in inf:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                # skip malformed lines
                continue

            text = obj.get("message") or obj.get("raw") or ""
            security_types = obj.get("securityTypes") or []
            matched_rule = obj.get("matchedRule") or ""
            attack_type = normalize_attack_type(security_types, matched_rule)
            is_attack = 1 if security_types or (isinstance(matched_rule, str) and matched_rule.startswith("security:")) else 0

            out = {
                "id": obj.get("id"),
                "text": text,
                "raw": obj.get("raw"),
                "attack_type": attack_type,
                "is_attack": is_attack,
                "severity": obj.get("severity"),
                "category": obj.get("category"),
                "securityTypes": security_types,
            }

            outf.write(json.dumps(out, ensure_ascii=False) + "\n")
            out_count += 1
            if len(samples) < 5:
                samples.append(out)

    print(f"Wrote {out_count} lines to {DST}")
    print("Sample lines:")
    for s in samples:
        print(json.dumps(s, ensure_ascii=False))


if __name__ == "__main__":
    main()
