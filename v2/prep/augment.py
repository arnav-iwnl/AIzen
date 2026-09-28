"""Obfuscation augmentation entry point.

Primary logic lives in ingest.normalize (synthetic generation of URL-encoded,
base64, mixed-case, and comment-injected attack variants). This module exposes
the same generator as a standalone utility and a `build` entrypoint that chains
normalize -> build_dataset.

Run (after ingest): python -m prep.augment
"""
import sys


def main():
    from ingest.normalize import _gen_synthetic, heuristic_attack
    import config

    config.ensure_dirs()
    ballot = config.TRAIN_BALLOT
    syn = ballot.replace(".jsonl", ".synth.jsonl")
    _gen_synthetic(ballot, syn)
    count = sum(1 for _ in open(syn, encoding="utf-8"))
    print(f"[augment] wrote synthetic-augmented ballot with {count} rows -> {syn}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
