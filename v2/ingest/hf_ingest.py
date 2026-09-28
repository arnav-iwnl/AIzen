"""Pull security-label corpora from Hugging Face Datasets.

Skips gracefully offline / if the `datasets` package is missing.

Run: python -m ingest.hf_ingest
"""
import os
import sys

import config

# .env is already loaded by `config` (HF_TOKEN etc.). Pass it to the HF client.
_HF_TOKEN = os.environ.get("HF_TOKEN") or None

_SOURCES = [
    # name, HF dataset id, text_field, label_field
    # Verified live (HTTP 200 + schema checked). text/label fields are exact.
    ("http-attack-requests", "SecureAI-SE/http-attack-requests", "request", "label"),
    ("web-attack-detection", "truongp/web-attack-detection", "Sentence", "Label"),
    ("web-attacks", "shengqin/web-attacks", "Payload", "text_label"),
]


def main():
    config.ensure_dirs()
    try:
        import datasets as ds
    except Exception as exc:  # noqa: BLE001
        print(f"[hf] 'datasets' not importable ({exc}); skipping Hugging Face sources.")
        return

    for name, hf_id, text_field, label_field in _SOURCES:
        try:
            data = ds.load_dataset(hf_id, split="train", token=_HF_TOKEN)
            rows = []
            for rec in data:
                text = rec.get(text_field) or rec.get("text") or rec.get("sentence")
                label = rec.get(label_field) or rec.get("label")
                if text:
                    rows.append({"text": str(text), "label": str(label)})
            dest = os.path.join(config.DATASETS_DIR, name)
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "hf.jsonl"), "w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(__import__("json").dumps(r, ensure_ascii=False) + "\n")
            print(f"[hf] {name}: {len(rows)} rows")
        except Exception as exc:  # noqa: BLE001
            print(f"[hf] failed {name}: {exc}")


if __name__ == "__main__":
    sys.exit(main())
