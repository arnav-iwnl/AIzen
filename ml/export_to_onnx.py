#!/usr/bin/env python3
"""Wrapper to run the v2 ONNX export from a top-level script.

This calls `v2/export/export_onnx.py` in-process after ensuring `v2` is importable
and provides CLI flags for dry-run and optional publish to Hugging Face via
`ml/publish_to_hf.py`.
"""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "v2"))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--publish", action="store_true", help="Publish runtime artifacts to HF after export")
    p.add_argument("--repo", default=os.environ.get("HF_REPO", "drowzy/aizen-siem"))
    p.add_argument("--token", default=os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN"))
    args = p.parse_args()

    # Dry-run: check for checkpoint
    ck = ROOT / "v2" / "data" / "best.pt"
    if args.dry_run:
        if ck.exists():
            print(f"[dry-run] checkpoint exists: {ck}")
            return 0
        else:
            print(f"[dry-run] missing checkpoint: {ck}")
            return 2

    # Run the v2 export
    try:
        from export.export_onnx import export
    except Exception as exc:
        print("Failed to import v2 export module:", exc)
        return 1

    rc = export()
    if rc != 0:
        print("Export returned non-zero:", rc)
        return rc

    # Optionally publish
    if args.publish:
        pub_cmd = [sys.executable, str(ROOT / "ml" / "publish_to_hf.py"), "--repo", args.repo, "--token", args.token]
        print("Publishing via:", " ".join(pub_cmd))
        res = os.spawnvp(os.P_WAIT, sys.executable, pub_cmd)
        if res != 0:
            print("Publish failed with", res)
            return res

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
