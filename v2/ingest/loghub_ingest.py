"""Fetch Loghub (LogPAI) corpora for NORMAL traffic baselines.

Mirrors the intent of server/scripts/pullLoghub.js but for v2. These real
Apache/OpenSSH logs provide the 'benign' class and operational categories that
the attack corpora lack.

Run: python -m ingest.loghub_ingest
"""
import os
import sys

import config
from ingest.common import download, unpack

_SOURCES = [
    ("loghub-apache", "https://zenodo.org/records/8196385/files/Apache.tar.gz?download=1"),
    ("loghub-openssh", "https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1"),
    # extra normal web traffic (research-friendly)
    ("nasa-http", "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/nginx_logs/nginx_logs"),
]


def main():
    config.ensure_dirs()
    for name, url in _SOURCES:
        try:
            if url.endswith(".tar.gz"):
                archive = download(url, os.path.join(config.DATASETS_DIR, f"{name}.tar.gz"), timeout=600)
                unpack(archive, os.path.join(config.DATASETS_DIR, name))
                print(f"[loghub] extracted {name}")
            else:
                dest = os.path.join(config.DATASETS_DIR, name, "raw.log")
                download(url, dest)
                print(f"[loghub] downloaded {name}")
        except Exception as exc:  # noqa: BLE001
            print(f"[loghub] failed {name}: {exc}")


if __name__ == "__main__":
    sys.exit(main())
