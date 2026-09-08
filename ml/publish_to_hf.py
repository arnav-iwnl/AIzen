#!/usr/bin/env python3
"""Upload v2 runtime artifacts to a Hugging Face model repo.

Supports selective uploads (runtime only, include data/datasets) and targeted
reverts (delete specific paths or prefixes) so you don't accidentally keep the
whole `v2/` folder in the model repo.

Usage examples:
  # dry-run upload runtime only
  python ml/publish_to_hf.py --dry-run --only-runtime

  # upload runtime + data/datasets
  python ml/publish_to_hf.py --repo drowzy/aizen-siem --token $HF_TOKEN --include-data

  # delete specific files from the repo (revert accidental upload)
  python ml/publish_to_hf.py --repo drowzy/aizen-siem --token $HF_TOKEN --revert-paths runtime/model.onnx v2/runtime/meta.json

  # delete by prefix (remove everything under `v2/` in the repo)
  python ml/publish_to_hf.py --repo drowzy/aizen-siem --token $HF_TOKEN --revert-prefix v2/
"""
import argparse
import json
import os
from pathlib import Path

try:
    from huggingface_hub import HfApi
except Exception:  # pragma: no cover
    HfApi = None


ROOT = Path(".")
RUNTIME_FILES = [
    (ROOT / "v2" / "runtime" / "model.onnx", "runtime/model.onnx"),
    (ROOT / "v2" / "runtime" / "model.onnx.data", "runtime/model.onnx.data"),
    (ROOT / "v2" / "runtime" / "meta.json", "runtime/meta.json"),
    (ROOT / "v2" / "runtime" / "tokenizer.js", "runtime/tokenizer.js"),
]


DEFAULT_DATA_FILES = [
    (ROOT / "v2" / "data" / "best.pt", "data/best.pt"),
    (ROOT / "v2" / "data" / "access.log", "data/access.log"),
    (ROOT / "v2" / "data" / "test.log", "data/test.log"),
    (ROOT / "v2" / "data" / "Apache_2k.log", "data/Apache_2k.log"),
    (ROOT / "v2" / "data" / "synthetic_error.log", "data/synthetic_error.log"),
]


def collect_dataset_files():
    # runtime dataset shards are under v2/data/datasets
    base = ROOT / "v2" / "data" / "datasets"
    out = []
    if not base.exists():
        return out
    for p in sorted(base.rglob("*")):
        if p.is_file():
            rel = p.relative_to(ROOT / "v2")
            out.append((p, Path("v2") / rel))
    return out


def collect_source_datasets():
    # source corpora (training sources) are under v2/datasets and are
    # potentially large; include only when explicitly requested.
    base = ROOT / "v2" / "datasets"
    out = []
    if not base.exists():
        return out
    for p in sorted(base.rglob("*")):
        if p.is_file():
            rel = p.relative_to(ROOT)
            out.append((p, rel))
    return out


def upload(
    repo_id: str,
    token: str,
    dry_run: bool = False,
    commit_message: str = None,
    include_runtime: bool = True,
    include_data: bool = False,
    include_source_datasets: bool = False,
):
    if HfApi is None:
        raise RuntimeError("huggingface_hub is not installed. pip install huggingface-hub")

    api = HfApi()
    commit_message = commit_message or "Add v2 runtime artifacts"

    to_upload = []
    if include_runtime:
        to_upload.extend(RUNTIME_FILES)
    if include_data:
        to_upload.extend(DEFAULT_DATA_FILES)
        to_upload.extend([(p, str(d)) for p, d in collect_dataset_files()])
    if include_source_datasets:
        to_upload.extend([(p, str(d)) for p, d in collect_source_datasets()])

    if not to_upload:
        print("No files selected for upload.")
        return

    for src, dest in to_upload:
        dest_str = dest if isinstance(dest, str) else str(dest).replace("\\", "/")
        if not src.exists():
            print(f"Skipping missing file: {src}")
            continue
        if dry_run:
            print(f"[dry-run] would upload {src} -> {repo_id}/{dest_str}")
            continue
        print(f"Uploading {src} -> {repo_id}/{dest_str} ...")
        api.upload_file(
            path_or_fileobj=str(src),
            path_in_repo=dest_str,
            repo_id=repo_id,
            token=token,
            repo_type="model",
            commit_message=commit_message,
        )
        print("OK")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", default=os.environ.get("HF_REPO", "drowzy/aizen-siem"))
    p.add_argument("--token", default=os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN"))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--only-runtime", action="store_true", help="Upload only runtime files (model.onnx + meta.json)")
    p.add_argument("--include-data", action="store_true", help="Also upload data files (best.pt + v2/data/datasets)")
    p.add_argument("--include-source-datasets", action="store_true", help="Also upload source corpora under v2/datasets (large, opt-in)")
    p.add_argument("--revert-prefix", nargs="*", help="Delete files in the HF repo with these prefixes (e.g. v2/ or data/)")
    p.add_argument("--revert-paths", nargs="*", help="Delete specific paths in the HF repo (e.g. runtime/model.onnx)")
    p.add_argument("--commit-message", default=None)
    args = p.parse_args()

    if not args.token and not args.dry_run:
        print("Error: no Hugging Face token provided. Set HF_TOKEN or use --dry-run.")
        return 2

    try:
        # Handle deletes first if requested
        api = HfApi() if HfApi is not None else None
        if args.revert_paths or args.revert_prefix:
            if api is None:
                print("huggingface_hub required to delete files from repo")
                return 1
            # delete specific paths
            for pth in (args.revert_paths or []):
                try:
                    print(f"Deleting {pth} from {args.repo} ...")
                    api.delete_file(path_in_repo=pth, repo_id=args.repo, token=args.token)
                    print("OK")
                except Exception as exc:  # pragma: no cover
                    print(f"Failed to delete {pth}: {exc}")
            # delete by prefix: list repo files and remove matching
            if args.revert_prefix:
                try:
                    files = api.list_repo_files(args.repo)
                    for pref in args.revert_prefix:
                        to_del = [f for f in files if f.startswith(pref)]
                        for f in to_del:
                            try:
                                print(f"Deleting {f} from {args.repo} ...")
                                api.delete_file(path_in_repo=f, repo_id=args.repo, token=args.token)
                                print("OK")
                            except Exception as exc:  # pragma: no cover
                                print(f"Failed to delete {f}: {exc}")
                except Exception as exc:  # pragma: no cover
                    print(f"Failed to list repo files: {exc}")

        include_runtime = True if not args.only_runtime is False else True
        include_data = bool(args.include_data)
        include_source = bool(args.include_source_datasets)
        # If --only-runtime specified, do not include data unless explicitly asked
        if args.only_runtime:
            include_runtime = True
            include_data = bool(args.include_data)

        upload(
            args.repo,
            args.token,
            dry_run=args.dry_run,
            commit_message=args.commit_message,
            include_runtime=include_runtime,
            include_data=include_data,
            include_source_datasets=include_source,
        )
    except Exception as exc:
        print("Upload failed:", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
