"""Entrypoint: build torch datasets + label artifacts from the ballot.

Run (after normalize/augment): python -m prep.build_dataset
"""
import sys


def main():
    import config
    config.ensure_dirs()
    from prep.dataset import build_datasets

    for syn in (False, True):
        train, val, meta = build_datasets(syn=syn)
        print(f"[build_dataset] synth={syn} train={meta['train_size']} val={meta['val_size']} "
              f"attack classes={len(meta['attack_index'])} cats={len(meta['category_index'])} sevs={len(meta['severity_index'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
