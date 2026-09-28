import React from 'react';
import { Target } from 'lucide-react';

/**
 * MITRE ATT&CK technique chips for a single real-time event.
 *
 * `ev.techniques` is what the DETECTOR concluded (rules + the deep model).
 * `ev.expectedTechniques` is what the vulnerable site said the request actually
 * was — ground truth, shipped alongside purely so a miss is visible instead of
 * silent. A match is a green tick, a miss is an amber "expected" chip, which
 * makes the detector's real accuracy observable on the live feed.
 */
export default function TechniqueChips({ ev, className = '' }) {
  const detected = ev?.techniques || [];
  const expected = ev?.expectedTechniques || [];
  if (!detected.length && !expected.length) return null;

  const detectedIds = new Set(detected.map((t) => t.id));

  return (
    <div className={`flex items-center gap-1 flex-wrap ${className}`}>
      <Target className="w-3 h-3 text-red-500/70 flex-shrink-0" />
      {detected.map((t) => (
        <a
          key={t.id}
          href={t.url || `https://attack.mitre.org/techniques/${String(t.id).replace('.', '/')}/`}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          title={`${t.name} — ${t.tactic}`}
          className="inline-flex items-center rounded border border-red-900/70 bg-red-500/10 px-1.5 py-0 font-mono text-[10px] font-semibold text-red-300 hover:bg-red-500/20 flex-shrink-0"
        >
          {t.id}
        </a>
      ))}
      {expected
        .filter((id) => !detectedIds.has(id))
        .map((id) => (
          <span
            key={`exp-${id}`}
            title="The vulnerable site says this route models this technique — the detector did not flag it (possible miss)"
            className="inline-flex items-center rounded border border-amber-800/70 bg-amber-500/10 px-1.5 py-0 font-mono text-[10px] font-semibold text-amber-300 flex-shrink-0"
          >
            expected {id}
          </span>
        ))}
    </div>
  );
}
