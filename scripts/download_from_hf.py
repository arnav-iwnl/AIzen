#!/usr/bin/env python3
"""
Download model from Hugging Face Hub at runtime.
Usage: python download_from_hf.py --repo-id your-username/aizen-model --output-dir ./v2/runtime
"""
import argparse
import os
import sys
from pathlib import Path

try:
    from huggingface_hub import hf_hub_download, snapshot_download
except ImportError:
    print("Error: huggingface_hub not installed. Run: pip install huggingface_hub")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Download model from Hugging Face Hub")
    parser.add_argument("--repo-id", required=True, help="HF repo ID (e.g., username/aizen-model)")
    parser.add_argument("--output-dir", default="./v2/runtime", help="Output directory")
    parser.add_argument("--revision", default="main", help="Git revision (branch, tag, or commit)")
    parser.add_argument("--token", help="HF token (for private repos)")
    parser.add_argument("--files", nargs="+", default=["model.onnx", "model.onnx.data", "meta.json", "tokenizer.js"],
                        help="Files to download")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Downloading from {args.repo_id} (rev: {args.revision}) to {args.output_dir}")

    try:
        # Download specific files
        downloaded = []
        for filename in args.files:
            try:
                path = hf_hub_download(
                    repo_id=args.repo_id,
                    filename=filename,
                    revision=args.revision,
                    token=args.token or os.getenv("HF_TOKEN"),
                    local_dir=".",  # download to current dir first
                    local_dir_use_symlinks=False,
                )
                # Move to output dir
                dst = Path(args.output_dir) / filename
                Path(path).replace(dst)
                print(f"  Downloaded: {filename}")
            except Exception as e:
                print(f"Warning: Failed to download {filename}: {e}")

        # Verify all files exist
        missing = []
        for f in ["model.onnx", "model.onnx.data", "meta.json"]:
            if not (Path(args.output_dir) / f).exists():
                missing.append(f)

        if missing:
            print(f"Warning: Missing required files: {missing}")
            sys.exit(1)

        print("Download complete!")
        print(f"Model ready at: {Path(args.output_dir).resolve()}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()