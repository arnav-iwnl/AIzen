# AIzen v2 — Adoption Guide (drop-in wiring, opt-in)

> Status: **documentation only.** v2 is fully isolated in `v2/` and the legacy
> `client/` + `server/` + `ml/` are untouched. This guide describes how to wire
> the v2 deep detector into the running Node server LATER, behind an **opt-in
> env toggle** so legacy stays identical until you flip it.

## Gate before wiring

Do **not** enable v2 until the exported model clears the gate:

```bash
cd v2/runtime && npm install
node mixed_benchmark.js     # requires v2/runtime/model.onnx + meta.json
# PASS: production-ready   (attack recall >= 0.95, benign precision >= 0.95)
```

## How the toggle works (concept)

Add one env key read by the server config:

```js
// server/config/app.config.js (after v2 wiring)
v2: {
  enabled: process.env.V2_CLASSIFIER === 'onnx',   // default off
  threshold: parseFloat(process.env.V2_THRESHOLD, 10) || null, // override
}
```

## Integration points (in the legacy server, when wiring)

1. **Load the runtime classifier once** at boot (lazy, non-blocking):
   ```js
   // server/ml/v2Bridge.js  (new)
   const { V2Classifier } = require('../../v2/runtime/onnx_classifier');
   exports.get = async () => (process.env.V2_CLASSIFIER === 'onnx') ? await V2Classifier.create() : null;
   ```

2. **detectorService.js** — when a `message` is classified, if the v2 model
   exists and flags `is_attack`, force `category = 'Security'`, `severity =
   'high'`, and raise confidence to the model's `attack_confidence`. This fixes
   the mixed-request blind spot (catches attacks the literal regexes miss).

3. **incidentService.js** — besides z-score bursts, emit an incident for any
   individual single line where v2 reports `is_attack` with
   `attack_confidence >= threshold`. This makes low-volume attacks ("mixed")
   surface even without a burst.

4. **Config** — `server/config/app.config.js` exposes `v2.enabled`; the
   classifier path checks it and falls back to the legacy LR/rules when off.

## Reprocessing a file through v2 (batch / upload path)

Uploaded logs are already deduplicated to patterns in `logStore`. Map each
pattern's `message` through `clf.classifyBatch(patterns.map(p => p.message))`
and fold the results into classification/incident stats.

## Deployment (free tier, Render)

- Model artifact is **committed** (`v2/runtime/model.onnx`, `meta.json`).
- `onnxruntime-node` runs on CPU in-process, threads=1, `ORT_ENABLE_BASIC`
  (see `onnx_classifier.js`) to stay under the 512MB free instance.
- Flip `V2_CLASSIFIER=onnx` in Render env vars when ready; keep it unset/`off`
  to run legacy.

## Rollback

Unset `V2_CLASSIFIER` (or set to anything but `onnx`) and redeploy/restart —
the server reverts to the legacy LR/rules path with no code change.
