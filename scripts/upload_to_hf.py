#!/usr/bin/env python3
"""
Upload model to Hugging Face Hub.
Usage: python upload_model.py --repo-id your-username/aizen-model --token YOUR_HF_TOKEN
"""
import argparse
import os
from pathlib import Path
from huggingface_hub import HfApi, create_repo, upload_folder


def main():
    parser = argparse.ArgumentParser(description="Upload model to Hugging Face Hub")
    parser.add_argument("--repo-id", required=True, help="HF repo ID (e.g., username/aizen-model)")
    parser.add_argument("--token", required=True, help="HF token (write access)")
    parser.add_argument("--model-dir", default="../v2/runtime", help="Path to model directory")
    parser.add_argument("--private", action="store_true", help="Make repo private")
    args = parser.parse_args()

    model_dir = Path(args.model_dir).resolve()
    if not model_dir.exists():
        raise FileNotFoundError(f"Model directory not found: {model_dir}")

    # Files to upload
    required_files = ["model.onnx", "model.onnx.data", "meta.json", "tokenizer.js"]
    for f in ["model.onnx", "model.onnx.data", "meta.json", "tokenizer.js"]:
        if not (Path(args.model_dir) / f).exists():
            print(f"Warning: {f} not found in {args.model_dir}")

    api = HfApi(token=args.token)
    repo_id = args.repo_id

    # Create repo if it doesn't exist
    try:
        create_repo(repo_id=repo_id, token=args.token, private=args.private, exist_ok=True)
        print(f"Repository {args.repo_id} ready")
    except Exception as e:
        print(f"Repo creation warning: {e}")

    # Upload files
    print(f"Uploading model files from {model_dir}...")
    api.upload_folder(
        folder_path=args.model_dir,
        repo_id=args.repo_id,
        token=args.token,
        path_in_repo=".",
        ignore_patterns=["*.log", "*.lock", "node_modules/", "__pycache__/", "*.pyc", "*.pyo", ".git/"],
    )
    print("Upload complete!")
    print(f"Model available at: https://huggingface.co/{args.repo_id}")


if __name__ == "__main__":
    main()