"""Download labeled attack corpora from Kaggle (public, research use).

Requires the `kaggle` CLI package and KAGGLE_USERNAME / KAGGLE_KEY env vars.
Each dataset is downloaded into v2/datasets/<name>/ with a source.yaml marker.
Skips gracefully if credentials are missing or a download fails.

Run: python -m ingest.kaggle_ingest
"""
import os
import sys

import config

# NOTE (2026): Kaggle has delisted most legacy personal research corpora
# (SQLi/XSS/web-attack/CSIC20?? slugs now return 404). Those attack classes are
# covered by the HF sources in hf_ingest.py, which are actively maintained.
# Only slugs verified live (HTTP 200) are listed here; other mirrors (e.g.
# chethuhn/network-intrusion-dataset, bertvankeulen/cicids-2017,
# mn0011/cicids2017-1m-sample-for-nids) are CICIDS *network-flow* tables that
# normalize.py skips (no text column), so they're not useful for the char-level
# HTTP/URL sequence classifier and are omitted.
_SOURCES = [
    # (name, kaggle dataset ref) — verified live + text modality (URLs)
    ("malicious-urls", "sid321axn/malicious-urls-dataset"),
]


def main():
    config.ensure_dirs()
    _legacy = os.environ.get("KAGGLE_USERNAME") and os.environ.get("KAGGLE_KEY")
    _new_token = os.environ.get("KAGGLE_API_TOKEN")
    if not (_legacy or _new_token):
        print("[kaggle] No credentials found. Provide one of:")
        print("[kaggle]   - legacy: KAGGLE_USERNAME + KAGGLE_KEY  (or ~/.kaggle/kaggle.json)")
        print("[kaggle]   - new   : KAGGLE_API_TOKEN  (or `kaggle auth login`)")
        print("[kaggle] Skipping Kaggle sources; rely on HF + Loghub instead.")
        return

    from kaggle.api.kaggle_api_extended import KaggleApi

    api = KaggleApi()
    api.authenticate()

    for name, ref in _SOURCES:
        dest = os.path.join(config.DATASETS_DIR, name)
        try:
            os.makedirs(dest, exist_ok=True)
            api.dataset_download_files(ref, path=dest, unzip=True)
            print(f"[kaggle] downloaded {name} -> {dest}")
        except Exception as exc:  # noqa: BLE001
            print(f"[kaggle] failed {name}: {exc}")


if __name__ == "__main__":
    sys.exit(main())
