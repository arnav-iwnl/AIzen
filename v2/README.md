# AIzen v2 — Deep Sequence Detector

Production-grade attack detection for AIzen, **fully isolated** from the legacy
`client/` + `server/` + `ml/` (which stay untouched and functional).

## Why v2 exists

The legacy detector is a char-TF-IDF + LogisticRegression trained on ~831
rule-auto-labeled patterns. It misses attacks mixed into normal traffic because:

1. The corpus is tiny and labeled by the same rules → no generalization to
   novel/obfuscated payloads.
2. Signature regexes are narrow (literal `acunetix`, `sqlmap`, `%27`) → encoded /
   base64 / mixed-case payloads slip through.
3. No dedicated attack/normal binary model (`attack.json`) was ever built.
4. Incident detection is pure z-score burst stats → low-volume attacks mixed in
   normal traffic don't trigger.

v2 trains a **character-level LSTM/Transformer** on large labeled corpora
(Kaggle + Hugging Face + Loghub), exports a small **quantized ONNX** artifact,
and serves predictions **in-process on CPU** via `onnxruntime-node` — so both
the real-time stream and uploaded-log batch paths classify with the same model
on the free-tier Render Node server.

## Repository layout

```
v2/
├── datasets/          # downloaded corpora (gitignored)
├── ingest/            # kaggle_ingest / hf_ingest / loghub_ingest / normalize
├── prep/              # tokenizer / dataset / augment (obfuscation)
├── train/             # config / models / train_deep / metrics
├── export/            # export_onnx (incl. INT8 quantization)
├── runtime/           # Node onnxruntime classifier + optional FastAPI sidecar
└── eval/              # eval_runner + mixed-benchmark gate
```

## Workflow

```bash
# 0) Install Python deps (local GPU machine)
pip install -r requirements.txt

# 1) Fetch datasets (Kaggle / HF / Loghub) → datasets/
python -m ingest.kaggle_ingest
python -m ingest.hf_ingest
python -m ingest.loghub_ingest

# 2) Normalize + preprocess + augment → data/ (wiki after ingest)
python -m ingest.normalize
python -m prep.build_dataset

# 3) Train deep model (GPU) and export quantized ONNX
python -m train.train_deep
python -m export.export_onnx

# 4) Eval (incl. mixed-benchmark gate)
python -m eval.eval_runner

# 5) Node runtime (server side)
cd runtime && npm install
node onnx_classifier.js            # single-line & batch classification
node mixed_benchmark.js            # reproduce the mixed-request scenario
```

## Runtime deployment (Render free tier, CPU ONNX in-process)

- The trained model is committed to `v2/runtime/model.onnx` (small, INT8).
- `onnxruntime-node` runs it on CPU, <1ms/line, in the **same Node process**.
- Enabling it in the live app is an **opt-in env toggle** (`V2_CLASSIFIER=onnx`),
  default off — legacy behavior is identical until flipped.
- See `/ADOPTION.md` (top of repo) for the drop-in wiring notes.

## Acceptance gate (mixed requests)

The model is only "production-ready" when it passes `mixed_benchmark.js`:

- attack **recall ≥ 0.95**
- benign **precision ≥ 0.95** (few/no false alarms)

Do not enable `V2_CLASSIFIER` until the exported ONNX clears this gate.
