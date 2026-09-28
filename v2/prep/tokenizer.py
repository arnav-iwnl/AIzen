"""Character-level tokenizer shared by train and runtime.

Vocab = 256 byte values + PAD + UNK. The same JSON artifact is loaded by the
Node runtime (v2/runtime/tokenizer.json) for parity between train and serve.
"""
import json
import os

import config

PAD = 0
UNK = 1
_BASE = 256


class CharTokenizer:
    def __init__(self, max_len=config.MAX_LEN):
        self.max_len = max_len

    @staticmethod
    def _window(text, max_len):
        """Keep the HEAD and the TAIL of an over-long string.

        Truncating at `[:max_len]` kept the timestamp/SIEM-envelope prefix and
        threw the payload away — and for SIEM alerts the payload is exactly what
        lives in the tail (v2/ingest/ossec_ingest.py:147 builds
        "<alert desc> <body>"). A 256-wide window is split so both ends survive.
        Must stay identical to tokenize() in v2/runtime/tokenizer.js.
        """
        if len(text) <= max_len:
            return text
        head = max_len // 2
        return text[:head] + text[-(max_len - head):]

    def encode(self, text: str):
        """Encode into a fixed-length sequence of ids (PAD right)."""
        text = self._window((text or "").lower(), self.max_len)
        ids = [ord(c) + 2 if ord(c) < _BASE else UNK for c in text]
        ids = ids[: self.max_len]
        ids += [PAD] * (self.max_len - len(ids))
        return ids

    def vocabulary_size(self):
        return _BASE + 2


def save_tokenizer(path=config.TOKENIZER_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"type": "char", "pad": PAD, "unk": UNK, "base": _BASE, "max_len": config.MAX_LEN}, fh)


def load_tokenizer(path=config.TOKENIZER_PATH):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
