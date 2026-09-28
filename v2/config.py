"""Shared configuration for AIzen v2 (data, training, export, runtime)."""
import os

V2_ROOT = os.path.dirname(os.path.abspath(__file__))

# Load v2/.env into os.environ (HF_TOKEN, KAGGLE_* etc.). Every module imports
# this, so tokens are visible to the ingest scripts. Graceful if dotenv missing.
_ENV_PATH = os.path.join(V2_ROOT, ".env")
try:
    from dotenv import load_dotenv
    load_dotenv(_ENV_PATH)
except Exception:
    pass  # ponytail: parse bare KEY=VAL ourselves rather than fail the run
    try:
        with open(_ENV_PATH, encoding="utf-8") as _fh:
            for _line in _fh:
                _s = _line.strip()
                if _s and not _s.startswith("#") and "=" in _s:
                    _k, _v = _s.split("=", 1)
                    _k = _k.strip()
                    if _k and _k not in os.environ:
                        os.environ[_k] = _v.strip().strip('"').strip("'")
    except OSError:
        pass
DATASETS_DIR = os.path.join(V2_ROOT, "datasets")
CACHE_DIR = os.path.join(V2_ROOT, "data")          # normalized intermediate
TRAIN_BALLOT = os.path.join(CACHE_DIR, "ballot.jsonl")   # (is_attack, attack_type, category, severity, message)
TOKENIZER_PATH = os.path.join(CACHE_DIR, "tokenizer.json")
RUNTIME_DIR = os.path.join(V2_ROOT, "runtime")
ONNX_PATH = os.path.join(RUNTIME_DIR, "model.onnx")
META_PATH = os.path.join(RUNTIME_DIR, "meta.json")

# ── Data ──────────────────────────────────────────────────────────────
MAX_LEN = 256            # char/token sequence length (pad/truncate)
SOURCE_CAP = 40000       # per-source cap on ballot rows (legacy log/text sets)
SIEM_CAP = 30000         # cap on local OSSEC/Wazuh ingest rows
ATTACK_TYPES = ["sql-injection", "xss", "path-traversal", "bruteforce", "scanner", "credential_probe", "other"]

# Open label space: the attack head is sized from whatever labels the corpus
# contains (prep/dataset.py), so MITRE technique ids ("T1110", "T1021.002") are
# first-class attack_type values. New ingest sources that ship technique
# annotations therefore add classes with no code change — the old hardcoded
# membership test silently folded them all into "other".
import re as _re
_TECHNIQUE_ID = _re.compile(r"^T\d{4}(\.\d{3})?$")


def is_valid_attack_type(label):
    """True for a legacy attack name, "none", or an ATT&CK technique id."""
    return label in ATTACK_TYPES or label == "none" or bool(_TECHNIQUE_ID.match(str(label or "")))

CATEGORIES = [
    "Security", "Startup", "Shutdown", "Worker Initialization", "Configuration",
    "Backend Communication", "Performance", "Network", "Resource Not Found",
    "Service Instability", "Request Processing", "Warning", "Unknown",
]
SEVERITIES = ["critical", "high", "medium", "low", "info"]

# ── Model / training ──────────────────────────────────────────────────
MODEL = "lstm"            # "lstm" | "transformer"
HIDDEN = 128
LAYERS = 2
EMB_DIM = 64
DROPOUT = 0.3
BATCH_SIZE = 128
EPOCHS = int(os.environ.get("V2_EPOCHS", "20"))  # env override so CPU experiments are possible
LR = 1e-3
WEIGHT_DECAY = 1e-4


def get_device():
    """Resolve device lazily (torch may not be installed in every process)."""
    if os.environ.get("V2_FORCE_CPU") == "1":
        return "cpu"
    try:
        import torch
        return "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        return "cpu"

# Class weighting for rare attack types
CLASS_BALANCE = True

# ── Acceptance / thresholds ───────────────────────────────────────────
ATTACK_THRESHOLD = 0.5   # tuned by eval; export writes final value to meta.json
MIXED_RECALL = 0.95
MIXED_BENIGN_PRECISION = 0.95

# Cross-domain holdout. The validation set must be a slice the model cannot
# train on, but it must NOT remove a whole domain from training: holding out
# 100% of the SIEM corpora while expecting the model to detect SIEM is
# incoherent, and measurably so — that configuration memorised the web corpora
# (train F1 0.989) and collapsed on the holdout (F1 0.417, 1998 false
# positives), because the only exposure it had to syslog/OSSEC line shapes was
# ~25 synthetic seeds.
#
# So: hold out a FRACTION of every dataset (generalisation to unseen lines
# within known formats), and keep HOLDOUT_EXCLUDE as a small fully-unseen domain
# that never trains, as an honest unseen-format probe.
HOLDOUT_FRACTION = float(os.environ.get("V2_HOLDOUT_FRACTION", "0.15"))
HOLDOUT_EXCLUDE = {
    d.strip() for d in os.environ.get("V2_HOLDOUT_EXCLUDE", "wazuh-tpfp").split(",") if d.strip()
}

# Corpus sources (overridable small/in-memory flag for CI without full downloads)
def ensure_dirs():
    for d in (DATASETS_DIR, CACHE_DIR, RUNTIME_DIR):
        os.makedirs(d, exist_ok=True)
