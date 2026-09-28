"""Build an experiment ballot from the current one.

exp3 isolates ONE variable: corpus mix. The 5 new ATT&CK technique classes have
only 30-60 rows each in the ballot, which cannot be learned reliably, so they are
folded back into "other" for this run. The open label space in prep/dataset.py
stays — this only decides what THIS experiment trains on.
"""
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SRC = "data/ballot.jsonl"
DST = "experiments/exp3/ballot.jsonl"

os.makedirs(os.path.dirname(DST), exist_ok=True)
folded = Counter()
out = Counter()
n = 0
with open(SRC, encoding="utf-8") as fin, open(DST, "w", encoding="utf-8") as fout:
    for line in fin:
        r = json.loads(line)
        n += 1
        at = r.get("attack_type", "none")
        if isinstance(at, str) and at.upper().startswith("T") and len(at) > 3:
            folded[at] += 1
            r["attack_type"] = "other"
            r["technique_folded_for"] = at
        out[r["attack_type"]] += 1
        fout.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"rows={n} -> {DST}")
print("folded thin technique classes into 'other':")
for k, v in folded.most_common():
    print(f"  {v:5d}  {k}")
print("resulting label space:")
for k, v in out.most_common():
    print(f"  {v:7d}  {k}")
