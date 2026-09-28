"""Shared ingestion helpers for AIzen v2."""
import json
import os
import shutil
import urllib.request
import tarfile
import zipfile


def mkdir(path):
    os.makedirs(path, exist_ok=True)
    return path


def append_jsonl(path, row):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False))
        fh.write("\n")


def download(url, dest, timeout=120):
    """Download a file with a simple progress-free GET (small corpora)."""
    mkdir(os.path.dirname(dest))
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest
    req = urllib.request.Request(url, headers={"User-Agent": "aizen-v2-data"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as fh:
        shutil.copyfileobj(r, fh)
    return dest


def unpack(archive, dest_dir):
    mkdir(dest_dir)
    if archive.endswith(".tar.gz") or archive.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(dest_dir)
    elif archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest_dir)
    return dest_dir
