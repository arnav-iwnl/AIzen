import React, { useEffect, useState } from 'react';
import { Cpu } from 'lucide-react';
import { getV2Status } from '../api';

/**
 * Which v2 model is live, and what it can actually emit.
 *
 * Deliberately more than a green dot. The deep model is a bounded second
 * opinion behind the rules, and the honest thing to show next to its verdicts
 * is the size of its label space: this runtime serves 7 attack classes, so a
 * `T1110` or `T1486` conclusion can only ever come from a rule, never from the
 * model. Hiding that would let the UI imply the model did more than it did.
 */
export default function V2ModelBadge() {
  const [state, setState] = useState(null);

  useEffect(() => {
    let alive = true;
    getV2Status()
      .then((json) => {
        if (!alive) return;
        const v2 = json?.data?.v2 || json?.v2;
        if (!v2) return setState({ kind: 'unknown' });
        if (!v2.enabled) return setState({ kind: 'off' });
        if (!v2.loaded) return setState({ kind: 'error' });
        const labels = v2.info?.attackLabels || [];
        setState({
          kind: 'on',
          threshold: v2.info?.threshold ?? null,
          labels: labels.filter((l) => l !== 'none'),
          soloMin: v2.info?.soloMinConfidence,
        });
      })
      .catch(() => alive && setState({ kind: 'error' }));
    return () => { alive = false; };
  }, []);

  if (!state || state.kind === 'unknown') return null;

  const tone = {
    on: 'border-emerald-900/70 bg-emerald-500/10 text-emerald-300',
    off: 'border-neutral-700 bg-neutral-800/60 text-neutral-400',
    error: 'border-red-900/70 bg-red-500/10 text-red-300',
  }[state.kind];

  // Deliberately a nested ternary, not an object literal keyed by state.kind:
  // an object literal evaluates every value, so the `on` branch would read
  // state.labels.length even when the badge is in the off/error state, where
  // labels was never set -- throwing "cannot read properties of undefined" and
  // taking the whole view down.
  const label =
    state.kind === 'on'
      ? `v2 model · ${state.labels.length} classes`
      : state.kind === 'off'
        ? 'v2 model off'
        : 'v2 model unavailable';

  const title =
    state.kind === 'on'
      ? `runtimev2 — attack classes: ${state.labels.join(', ')}\n` +
        `attack threshold: ${state.threshold}\n` +
        `escalates a rules-clean line only above confidence ${state.soloMin}`
      : 'The deep model is a second opinion behind the deterministic rules.';

  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[10px] font-semibold ${tone}`}
    >
      <Cpu className="w-3 h-3" />
      {label}
    </span>
  );
}
