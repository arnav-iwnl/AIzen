import React, { useState, useEffect, useCallback } from 'react';
import {
  Upload, Play, CheckCircle, AlertTriangle, Activity,
  Clock, Shield, Zap, BarChart3, RotateCcw, FileText,
  TrendingUp, Search, Loader2, Download, Radar
} from 'lucide-react';
import {
  Button, Badge, Card, CardHeader, CardTitle,
  CardDescription, CardContent, Tabs, TabsList,
  TabsTrigger, TabsContent
} from '../components/ui';
import {
  checkHealth, classifyLogs, generateTimeline, analyzeRootCause, uploadLogFile, detectIncidents
} from '../api';

// ── Pipeline Stepper ─────────────────────────────────────────────────────────
function PipelineStepper({ currentStep: _currentStep, stepStatus }) {
  const steps = [
    { key: 'upload', label: 'Upload', icon: Upload },
    { key: 'classify', label: 'Classify', icon: Search },
    { key: 'timeline', label: 'Timeline', icon: Activity },
    { key: 'rootcause', label: 'Root Cause', icon: AlertTriangle },
  ];

  return (
    <div className="flex flex-col md:flex-row items-center md:items-center gap-2 py-4 w-full">
      {steps.map((step, i) => {
        const status = stepStatus[step.key] || 'pending';
        const isDone = status === 'done';
        const isActive = status === 'active';
        const StepIcon = isDone ? CheckCircle : step.icon;

        let bgClass = "bg-transparent border-neutral-800";
        let iconBg = "bg-neutral-800 text-neutral-400";
        let textClass = "text-neutral-400";

        if (isActive) {
          bgClass = "bg-orange-500/20 border-orange-500";
          iconBg = "bg-orange-500 text-white";
          textClass = "text-orange-300";
        } else if (isDone) {
          bgClass = "bg-emerald-500/20 border-emerald-500";
          iconBg = "bg-emerald-500 text-white";
          textClass = "text-emerald-400";
        }

        return (
          <div key={step.key} className="flex flex-col md:flex-row items-start md:items-center gap-2 flex-shrink-0">
            <div className={`flex items-center gap-2 px-4 py-2 rounded-full border transition-all duration-300 ${bgClass} ${isActive || isDone ? 'opacity-100' : 'opacity-50'}`}>
              <div className={`flex items-center justify-center w-6 h-6 rounded-full ${iconBg}`}>
                {isActive ? <Loader2 className="w-3 h-3 animate-spin" /> : <StepIcon className="w-3 h-3" />}
              </div>
              <span className={`text-sm font-semibold ${textClass}`}>
                {step.label}
              </span>
            </div>
            {i < steps.length - 1 && (
              <div className={`w-0.5 h-6 md:w-8 md:h-0.5 ml-7 md:ml-0 transition-colors duration-300 ${isDone ? 'bg-emerald-500' : 'bg-neutral-800'}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Metric Card ──────────────────────────────────────────────────────────────
function MetricCard({ label, value, colorClass, icon: MetricIcon }) {
  return (
    <Card className="bg-neutral-900 border-neutral-700">
      <CardContent className="p-4 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-sm text-neutral-400">{label}</span>
          {MetricIcon && <MetricIcon className={`w-4 h-4 ${colorClass}`} />}
        </div>
        <div className={`text-3xl font-bold font-mono ${colorClass}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

// ── Category Colors ──────────────────────────────────────────────────────
const CATEGORY_COLORS = {
  'Startup': '#22d3ee', 'Shutdown': '#a78bfa', 'Configuration': '#60a5fa',
  'Module Lifecycle': '#818cf8', 'Worker Management': '#34d399', 'Request Processing': '#2dd4bf',
  'Client Error (4xx)': '#fb923c', 'Server Error (5xx)': '#f87171', 'Resource Not Found': '#fbbf24',
  'Backend Communication': '#38bdf8', 'Performance': '#e879f9', 'Security': '#f43f5e',
  'Network': '#4ade80', 'Warning': '#facc15', 'Clean': '#10b981',
  'Error': '#ef4444', 'Worker Initialization': '#34d399',
};

function getCategoryColor(category) {
  return CATEGORY_COLORS[category] || '#94a3b8';
}

// ── Pie Chart (pure SVG) ─────────────────────────────────────────────────
function PieChart({ data, size = 220 }) {
  const [hovered, setHovered] = React.useState(null);
  const cx = size / 2;
  const cy = size / 2;
  const radius = size / 2 - 8;
  const innerRadius = radius * 0.55; // donut

  const total = data.reduce((s, d) => s + d.logCount, 0);
  if (total === 0) return null;

  let cumulative = 0;
  const arcs = data.map((d, i) => {
    const startAngle = (cumulative / total) * 2 * Math.PI - Math.PI / 2;
    cumulative += d.logCount;
    const endAngle = (cumulative / total) * 2 * Math.PI - Math.PI / 2;
    return { ...d, startAngle, endAngle, index: i };
  });

  function arcPath(startAngle, endAngle, r, ir) {
    const largeArc = endAngle - startAngle > Math.PI ? 1 : 0;
    const sx = cx + r * Math.cos(startAngle);
    const sy = cy + r * Math.sin(startAngle);
    const ex = cx + r * Math.cos(endAngle);
    const ey = cy + r * Math.sin(endAngle);
    const isx = cx + ir * Math.cos(endAngle);
    const isy = cy + ir * Math.sin(endAngle);
    const iex = cx + ir * Math.cos(startAngle);
    const iey = cy + ir * Math.sin(startAngle);
    return `M${sx},${sy} A${r},${r} 0 ${largeArc} 1 ${ex},${ey} L${isx},${isy} A${ir},${ir} 0 ${largeArc} 0 ${iex},${iey} Z`;
  }

  return (
    <div className="relative inline-block">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label="Donut chart showing log category distribution. Detailed data available in the table.">
        {arcs.map((arc) => {
          const isHovered = hovered === arc.index;
          const color = getCategoryColor(arc.category);
          return (
            <path
              key={arc.index}
              className="focus:outline-none"
              d={arcPath(arc.startAngle, arc.endAngle, isHovered ? radius + 4 : radius, isHovered ? innerRadius - 2 : innerRadius)}
              fill={color}
              stroke="#0a0a0a"
              strokeWidth="2"
              opacity={hovered === null || isHovered ? 1 : 0.4}
              style={{ transition: 'all 0.2s ease-out', cursor: 'pointer' }}
              onMouseEnter={() => setHovered(arc.index)}
              onMouseLeave={() => setHovered(null)}
              onFocus={() => setHovered(arc.index)}
              onBlur={() => setHovered(null)}
              tabIndex={0}
              aria-label={`${arc.category}: ${arc.logCount} logs, ${arc.percentage}%`}
              role="graphics-symbol"
            />
          );
        })}
        <text x={cx} y={cy - 8} textAnchor="middle" fill="#fff" fontSize="22" fontWeight="bold" aria-hidden="true">
          {total.toLocaleString()}
        </text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill="#9ca3af" fontSize="11" aria-hidden="true">
          total logs
        </text>
      </svg>

      {hovered !== null && arcs[hovered] && (
        <div className="absolute z-20 pointer-events-none bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 shadow-xl text-xs"
          style={{ top: '50%', left: '50%', transform: 'translate(-50%, -130%)' }}
          aria-hidden="true"
        >
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: getCategoryColor(arcs[hovered].category) }} />
            <span className="font-bold text-white">{arcs[hovered].category}</span>
          </div>
          <div className="text-neutral-300">
            {arcs[hovered].logCount.toLocaleString()} logs ({arcs[hovered].percentage}%)
          </div>
          <div className="text-neutral-400 mt-0.5">
            {arcs[hovered].patternCount} unique pattern{arcs[hovered].patternCount !== 1 ? 's' : ''}
          </div>
        </div>
      )}
    </div>
  );
}

function PieLegend({ data }) {
  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-2">
      {data.map((d, i) => (
        <div key={i} className="flex items-center gap-2 text-sm">
          <div className="w-3 h-3 rounded-sm flex-shrink-0" style={{ background: getCategoryColor(d.category) }} />
          <span className="text-neutral-300 truncate">{d.category}</span>
          <span className="text-neutral-400 ml-auto tabular-nums">{d.percentage}%</span>
        </div>
      ))}
    </div>
  );
}

// ── Panel components (shared by tabs UI and PDF print report) ──────────────
function IncidentsPanel({ incidents }) {
  return (
    <>
      <div className="flex items-center gap-3 flex-wrap">
        <Radar className="w-6 h-6 text-fuchsia-400" />
        <h2 className="text-xl font-bold text-white">Incident Detection</h2>
        <Badge variant="outline" className="border-neutral-700 text-neutral-400">{incidents?.processingTimeMs}ms</Badge>
        <Badge variant="secondary" className="text-emerald-400">Local engine — no LLM</Badge>
      </div>

      {incidents?.stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <MetricCard label="Total Logs" value={incidents.stats.totalLogs?.toLocaleString() || '—'} colorClass="text-neutral-300" icon={FileText} />
          <MetricCard label="Windows Analyzed" value={incidents.stats.bucketsAnalyzed || '—'} colorClass="text-blue-400" icon={Clock} />
          <MetricCard label="Novel Patterns" value={incidents.stats.novelPatterns || 0} colorClass="text-amber-400" icon={TrendingUp} />
          <MetricCard label="Escalation Chains" value={incidents.stats.escalationChains || 0} colorClass="text-orange-400" icon={Activity} />
          <MetricCard label="Baseline Errors/Window" value={incidents.stats.baseline?.meanSeverePerBucket ?? '—'} colorClass="text-fuchsia-400" icon={BarChart3} />
        </div>
      )}

      {incidents?.incidents?.length === 0 && (
        <Card className="bg-neutral-800/50 border-neutral-700">
          <CardContent className="p-6 flex items-center gap-4">
            <CheckCircle className="w-8 h-8 text-emerald-400 flex-shrink-0" />
            <div>
              <h3 className="font-bold text-white">No incidents detected</h3>
              <p className="text-sm text-neutral-400">Log activity stayed within baseline — no error bursts, novel error patterns, or escalation chains found.</p>
            </div>
          </CardContent>
        </Card>
      )}

      {incidents?.incidents?.map((inc, i) => (
        <Card key={i} className={`border ${inc.severity === 'critical' ? 'border-red-800 bg-red-950/20' : inc.severity === 'high' ? 'border-orange-800 bg-orange-950/10' : 'border-neutral-700 bg-neutral-800/50'}`}>
          <CardContent className="p-5 space-y-4">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant={inc.severity === 'critical' ? 'destructive' : inc.severity === 'high' ? 'warning' : 'secondary'} className="uppercase">
                {inc.severity}
              </Badge>
              <h3 className="font-bold text-white">{inc.title}</h3>
              <div className="flex gap-1.5 ml-auto flex-wrap">
                {inc.signals?.map((sig, j) => (
                  <Badge key={j} variant="outline" className="border-fuchsia-800 text-fuchsia-300 text-[10px]">
                    {sig}
                  </Badge>
                ))}
              </div>
            </div>

            <p className="text-sm text-neutral-400 leading-relaxed">{inc.summary}</p>

            {inc.windowStart && (
              <p className="text-xs text-neutral-500 font-mono">{inc.windowStart} → {inc.windowEnd}</p>
            )}

            {inc.zScore != null && (
              <p className="text-xs text-fuchsia-300 font-mono">z-score: {inc.zScore}σ</p>
            )}

            {inc.topPatterns?.length > 0 && (
              <div className="space-y-1 bg-black/40 p-3 rounded-md border border-neutral-700">
                <p className="text-[10px] uppercase tracking-wider text-neutral-500 font-semibold">Top patterns</p>
                {inc.topPatterns.map((p, j) => (
                  <p key={j} className="text-xs text-neutral-300 font-mono truncate hover:whitespace-normal flex gap-2">
                    <span className="text-fuchsia-400 flex-shrink-0">x{p.count}</span>
                    <span className="flex-shrink-0 text-neutral-500">{p.category}</span>
                    <span className="truncate">{p.message}</span>
                  </p>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </>
  );
}

function TimelinePanel({ timeline, timings }) {
  return (
    <>
      <div className="flex items-center gap-3">
        <Activity className="w-6 h-6 text-blue-400" />
        <h2 className="text-xl font-bold text-white">Incident Timeline</h2>
        <Badge variant="outline" className="border-neutral-700 text-neutral-400">{timings.timeline}s</Badge>
      </div>

      {timeline?.overallSummary && (
        <Card className="bg-blue-500/10 border-blue-500/20">
          <CardContent className="p-4">
            <p className="text-sm text-blue-100">{timeline.overallSummary}</p>
          </CardContent>
        </Card>
      )}

      <div className="pl-4 border-l-2 border-neutral-700 space-y-8 mt-8">
        {timeline?.timeline?.map((event, idx) => (
          <div className="relative" key={idx}>
            <div className={`absolute -left-[21px] top-1 w-3 h-3 rounded-full border-2 border-neutral-900 ${event.severity === 'critical' ? 'bg-red-500' :
              event.severity === 'error' ? 'bg-orange-500' :
                event.severity === 'warning' ? 'bg-amber-500' :
                  'bg-blue-500'
              }`} />

            <div className="flex items-center gap-2 mb-1">
              <Badge variant={event.severity === 'critical' ? 'destructive' : event.severity === 'error' ? 'warning' : 'secondary'} className="text-[10px] px-1.5 py-0">
                {event.severity?.toUpperCase()}
              </Badge>
              <span className="text-xs text-neutral-400 font-mono">{event.timestamp}</span>
            </div>

            <h4 className="font-bold text-white mb-1">{event.eventTitle}</h4>
            <p className="text-sm text-neutral-400 mb-3">{event.summary}</p>

            {event.escalationPath?.length > 0 && (
              <div className="mb-3 bg-neutral-800/60 border border-neutral-700 rounded-lg p-3">
                <p className="text-[10px] uppercase tracking-wider text-neutral-500 font-semibold mb-2">Escalation Path</p>
                <div className="space-y-0">
                  {event.escalationPath.map((step, stepIdx) => {
                    const dotColor =
                      step.level === 'error' || step.level === 'crit' || step.level === 'critical' ? 'bg-red-500' :
                        step.level === 'warn' || step.level === 'warning' ? 'bg-amber-500' :
                          'bg-blue-500';
                    const lineColor =
                      step.level === 'error' || step.level === 'crit' || step.level === 'critical' ? 'bg-red-500/30' :
                        step.level === 'warn' || step.level === 'warning' ? 'bg-amber-500/30' :
                          'bg-blue-500/30';
                    const textColor =
                      step.level === 'error' || step.level === 'crit' || step.level === 'critical' ? 'text-red-400' :
                        step.level === 'warn' || step.level === 'warning' ? 'text-amber-400' :
                          'text-blue-400';
                    const isLast = stepIdx === event.escalationPath.length - 1;

                    return (
                      <div key={stepIdx} className="flex items-stretch gap-3">
                        <div className="flex flex-col items-center w-4 flex-shrink-0">
                          <div className={`w-2.5 h-2.5 rounded-full ${dotColor} mt-1.5 flex-shrink-0 ring-2 ring-neutral-900`} />
                          {!isLast && <div className={`w-0.5 flex-1 min-h-[16px] ${lineColor}`} />}
                        </div>
                        <div className={`pb-2 ${isLast ? '' : 'pb-3'}`}>
                          <div className="flex items-center gap-2">
                            <span className={`text-[10px] font-bold uppercase ${textColor}`}>{step.level}</span>
                            {step.timestamp && (
                              <span className="text-[10px] text-neutral-600 font-mono">{step.timestamp}</span>
                            )}
                          </div>
                          <p className="text-xs text-neutral-400 leading-relaxed">{step.description}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {event.supportingEvidence?.length > 0 && (
              <div className="space-y-1 bg-neutral-800/50 p-3 rounded-md border border-neutral-700">
                {event.supportingEvidence.map((ev, j) => (
                  <p key={j} className="text-xs text-neutral-400 font-mono truncate hover:whitespace-normal">
                    → {ev}
                  </p>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </>
  );
}

function RootCausePanel({ rootCause, timings }) {
  return (
    <>
      <div className="flex items-center gap-3">
        <AlertTriangle className="w-6 h-6 text-red-500" />
        <h2 className="text-xl font-bold text-white">Root Cause & Recovery</h2>
        <Badge variant="outline" className="border-neutral-700 text-neutral-400">{timings.rootcause}s</Badge>
      </div>

      <Card className="bg-red-500/10 border-red-500/20">
        <CardHeader className="pb-2">
          <CardTitle className="text-red-400 text-lg">Identified Root Cause</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-red-100/90 leading-relaxed text-sm">
            {rootCause?.analysis?.rootCause}
          </p>
        </CardContent>
      </Card>

      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <h3 className="font-semibold text-white">Causal Chain</h3>
          <div className="space-y-3">
            {rootCause?.analysis?.causalChain?.map((step, i) => (
              <div key={i} className="flex gap-3 items-start">
                <div className="flex-shrink-0 w-6 h-6 rounded bg-neutral-800 text-neutral-400 flex items-center justify-center text-xs font-bold">
                  {i + 1}
                </div>
                <p className="text-sm text-neutral-300 pt-0.5">{step}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="font-semibold text-white">System Impact</h3>
          <p className="text-sm text-neutral-400 leading-relaxed bg-neutral-800/50 p-4 rounded-lg border border-neutral-700">
            {rootCause?.analysis?.impact}
          </p>
        </div>
      </div>

      <div className="pt-4">
        <h3 className="font-semibold text-emerald-400 mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4" /> Recovery Recommendations
        </h3>
<div className="space-y-3">
                      {rootCause?.analysis?.recommendations?.map((rec, i) => (
                        <Card key={i} className="bg-neutral-800/50 border-neutral-700">
                          <CardContent className="p-4">
                            <div className="flex items-center gap-2 mb-2 flex-wrap">
                              <Badge variant={rec.priority === 'high' ? 'destructive' : rec.priority === 'medium' ? 'warning' : 'secondary'} className="h-fit">
                                {rec.priority?.toUpperCase()}
                              </Badge>
                              <h4 className="font-bold text-white text-sm">{rec.action}</h4>
                            </div>
                            <p className="text-sm text-neutral-400 mb-3 leading-relaxed">{rec.rationale}</p>

                            {rec.files?.length > 0 && (
                              <div className="mb-3">
                                <p className="text-[10px] uppercase tracking-wider text-neutral-500 font-semibold mb-1.5">Targeted files ({rec.files.length})</p>
                                <div className="flex flex-wrap gap-1.5">
                                  {rec.files.map((f, j) => (
                                    <code key={j} className="px-2 py-1 text-xs bg-black/50 border border-neutral-700 rounded font-mono text-orange-300 break-all">
                                      {f.path} <span className="text-neutral-500">×{f.count}</span>
                                    </code>
                                  ))}
                                </div>
                              </div>
                            )}

                            {rec.routes?.length > 0 && (
                              <div className="mb-3">
                                <p className="text-[10px] uppercase tracking-wider text-neutral-500 font-semibold mb-1.5">Targeted routes ({rec.routes.length})</p>
                                <div className="flex flex-wrap gap-1.5">
                                  {rec.routes.map((r, j) => (
                                    <code key={j} className="px-2 py-1 text-xs bg-black/50 border border-neutral-700 rounded font-mono text-sky-300 break-all">
                                      {r.path} <span className="text-neutral-500">×{r.count}</span>
                                    </code>
                                  ))}
                                </div>
                              </div>
                            )}

                            {rec.sources?.length > 0 && (
                              <div className="mb-3">
                                <p className="text-[10px] uppercase tracking-wider text-neutral-500 font-semibold mb-1.5">Source IPs ({rec.sources.length})</p>
                                <div className="flex flex-wrap gap-1.5">
                                  {rec.sources.map((s, j) => (
                                    <code key={j} className="px-2 py-1 text-xs bg-black/50 border border-neutral-700 rounded font-mono text-rose-300 break-all">
                                      {s.ip} <span className="text-neutral-500">×{s.count}</span>
                                    </code>
                                  ))}
                                </div>
                              </div>
                            )}

                            {rec.steps?.length > 0 && (
                              <ol className="space-y-1.5">
                                {rec.steps.map((step, j) => (
                                  <li key={j} className="flex gap-2 text-sm text-neutral-300">
                                    <span className="w-5 h-5 rounded bg-orange-500/10 text-orange-400 flex items-center justify-center text-xs font-bold flex-shrink-0 mt-0.5">{j + 1}</span>
                                    <span className="leading-relaxed">{step}</span>
                                  </li>
                                ))}
                              </ol>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <Card className="bg-neutral-800/50 border-neutral-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-neutral-300">Confidence Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <span className="text-3xl font-bold text-orange-400 font-mono">{rootCause?.analysis?.confidence || 0}%</span>
              <div className="flex-1 h-2 bg-neutral-700 rounded-full overflow-hidden">
                <div className="h-full rounded-full bg-orange-500" style={{ width: `${rootCause?.analysis?.confidence || 0}%` }} />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-neutral-800/50 border-neutral-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-neutral-300">Analysis Notes</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-neutral-400 leading-relaxed">{rootCause?.analysis?.analysisNotes || '—'}</p>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

// ── Main Upload View ───────────────────────────────────────────────────────
export default function UploadView() {
  const [health, setHealth] = useState(null);
  const [stepStatus, setStepStatus] = useState({});
  const [currentStep, setCurrentStep] = useState('upload');
  const [classification, setClassification] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [rootCause, setRootCause] = useState(null);
  const [incidents, setIncidents] = useState(null);
  const [error, setError] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [timings, setTimings] = useState({});
  const [selectedModel, setSelectedModel] = useState('gemini-2.5-flash');

  const handleExportPDF = () => {
    window.print();
  };

  const setStep = (key, status) => {
    setStepStatus(prev => ({ ...prev, [key]: status }));
    if (status === 'active') setCurrentStep(key);
  };

  // ── Run full pipeline ────────────────────────────────────────────────────
  const runPipeline = useCallback(async (file) => {
    setError('');
    setClassification(null);
    setTimeline(null);
    setRootCause(null);
    setIncidents(null);
    setTimings({});

    try {
      setStep('upload', 'active');
      if (file) {
        await uploadLogFile(file);
      }
      setStep('upload', 'done');

      setStep('classify', 'active');
      const t1 = Date.now();
      const classRes = await classifyLogs(null, selectedModel);
      const classTime = ((Date.now() - t1) / 1000).toFixed(1);
      setClassification(classRes.data);
      setTimings(prev => ({ ...prev, classify: classTime }));
      setStep('classify', 'done');

      const detRes = await detectIncidents();
      setIncidents(detRes.data);

      setStep('timeline', 'active');
      const t2 = Date.now();
      const timeRes = await generateTimeline({ focus: 'errors', maxEvents: 8, model: selectedModel });
      const timeTime = ((Date.now() - t2) / 1000).toFixed(1);
      setTimeline(timeRes.data);
      setTimings(prev => ({ ...prev, timeline: timeTime }));
      setStep('timeline', 'done');

      setStep('rootcause', 'active');
      const t3 = Date.now();
      const dominantSymptom = classRes.data?.summary?.dominantCategory || 'Server Errors';
      const rcRes = await analyzeRootCause(dominantSymptom, selectedModel);
      const rcTime = ((Date.now() - t3) / 1000).toFixed(1);
      setRootCause(rcRes.data);
      setTimings(prev => ({ ...prev, rootcause: rcTime }));
      setStep('rootcause', 'done');

    } catch (err) {
      console.error(err);
      setError(err.message || 'Pipeline failed');
      setStepStatus(prev => {
        const next = { ...prev };
        Object.keys(next).forEach(k => { if (next[k] === 'active') next[k] = 'error' });
        return next;
      });
    }
  }, [selectedModel]);

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer?.files?.[0];
    if (file) runPipeline(file);
  };

  const handleFileSelect = (e) => {
    const file = e.target.files?.[0];
    if (file) runPipeline(file);
  };

  useEffect(() => {
    checkHealth()
      .then(d => setHealth(d))
      .catch(() => setHealth({ status: 'error' }));
  }, []);

  const isRunning = Object.values(stepStatus).includes('active');
  const isDone = stepStatus.rootcause === 'done';
  const totalTokensUsed = (classification?.usage?.totalTokenCount || 0) +
    (timeline?.usage?.totalTokenCount || 0) +
    (rootCause?.usage?.totalTokenCount || 0);

  return (
    <div className="p-6 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 print:space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 bg-orange-500 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(249,115,22,0.15)]">
            <Upload className="w-6 h-6 text-black" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Upload Logs</h1>
            <p className="text-sm text-neutral-400 font-medium">Classify, build a timeline, and identify root cause</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {isDone && (
            <Button variant="outline" size="sm" className="border-neutral-700 text-neutral-300 hover:bg-neutral-800 hover:text-white print:hidden" onClick={handleExportPDF}>
              <Download className="w-4 h-4 mr-2" />
              Export PDF
            </Button>
          )}
          <Badge variant={health?.data?.status === 'healthy' ? 'success' : 'destructive'} className="shadow-sm">
            {health?.data?.status === 'healthy' ? 'Backend Online' : 'Backend Offline'}
          </Badge>
        </div>
      </div>

      {/* ── Pipeline Progress ────────────────────────────────────────── */}
      <div className="print:hidden">
        <PipelineStepper currentStep={currentStep} stepStatus={stepStatus} />
      </div>

      {/* ── Upload / Landing Area ───────────────────────────────────── */}
      {!isDone && !isRunning && !error && (
        <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div
            role="button"
            tabIndex={0}
            aria-label="Upload server logs. Drag and drop a file, or press enter to browse."
            className={`border-2 border-dashed rounded-2xl p-6 md:p-16 text-center cursor-pointer transition-all duration-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-500 focus-visible:ring-offset-2 focus-visible:ring-offset-neutral-900 ${isDragging ? 'border-orange-500 bg-orange-500/10 scale-[1.02]' : 'border-neutral-800 bg-neutral-900/50 hover:border-orange-500/50 hover:bg-neutral-900'
              }`}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => document.getElementById('file-input').click()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                document.getElementById('file-input').click();
              }
            }}
          >
            <input id="file-input" type="file" accept=".log,.txt" className="hidden" onChange={handleFileSelect} />
            <div className="flex flex-col items-center gap-4 max-w-md mx-auto">
              <div className="w-16 h-16 bg-orange-500/20 rounded-full flex items-center justify-center">
                <Upload className="w-8 h-8 text-orange-400" />
              </div>
              <h2 className="text-xl font-bold text-white">Upload Server Logs</h2>
              <p className="text-sm text-neutral-400 text-balance leading-relaxed">
                Drag & drop your .log file here, or click to browse.
                AIzen will classify errors, build an incident timeline, and identify the root cause instantly.
              </p>

              <div className="w-full mt-2 text-left" onClick={(e) => e.stopPropagation()}>
                <label htmlFor="landing-model-select" className="block text-sm font-medium text-neutral-400 mb-2">
                  Select Analysis Model
                </label>
                <select
                  id="landing-model-select"
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value)}
                  disabled={isRunning}
                  className="bg-neutral-900 border border-neutral-700 text-neutral-300 text-sm rounded-lg focus:ring-orange-500 focus:border-orange-500 block w-full p-2.5"
                >
                  <option value="gemini-2.5-flash">Local Engine</option>
                </select>
              </div>

              <div className="flex items-center gap-4 w-full py-4">
                <div className="h-px bg-neutral-800 flex-1" />
                <span className="text-xs text-neutral-600 font-medium uppercase tracking-wider">or</span>
                <div className="h-px bg-neutral-800 flex-1" />
              </div>
              <Button
                variant="secondary"
                className="w-full bg-orange-500 hover:bg-orange-600 text-white"
                onClick={(e) => { e.stopPropagation(); runPipeline(null); }}
              >
                <Play className="w-4 h-4 mr-2" />
                Use Sample Apache Logs
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ── Loading State ─────────────────────────────────────────────── */}
      {isRunning && (
        <div className="animate-in fade-in zoom-in-95 duration-300">
          <Card className="bg-neutral-900/50 border-neutral-800 py-8 md:py-16 px-2 md:px-0" aria-live="polite" aria-busy="true">
            <CardContent className="flex flex-col items-center justify-center gap-6">
              <div className="relative">
                <div className="absolute inset-0 bg-orange-500/20 blur-xl rounded-full" />
                <Loader2 className="w-12 h-12 text-orange-400 animate-spin relative" />
              </div>
              <div className="text-center space-y-2">
                <h3 className="text-lg md:text-xl font-bold text-white text-balance px-4">
                  {currentStep === 'upload' && 'Ingesting & parsing logs...'}
                  {currentStep === 'classify' && 'Classifying log patterns locally...'}
                  {currentStep === 'timeline' && 'Generating incident timeline...'}
                  {currentStep === 'rootcause' && 'Analyzing root cause & recovery...'}
                </h3>
                <p className="text-sm text-neutral-400 animate-pulse">
                  Runs fully locally — usually under a second.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Error State ─────────────────────────────────────────────── */}
      {error && (
        <div className="animate-in fade-in slide-in-from-top-4">
          <Card className="bg-red-950/30 border-red-900/50" aria-live="assertive">
            <CardContent className="flex items-center gap-4 p-6">
              <div className="w-10 h-10 bg-red-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                <AlertTriangle className="w-5 h-5 text-red-500" />
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-semibold text-red-400">Pipeline Execution Failed</h4>
                <p className="text-sm text-red-300/80 mt-1">{error}</p>
              </div>
              <Button variant="outline" className="border-red-900/50 hover:bg-red-900/30" onClick={() => { setError(''); setStepStatus({}); setCurrentStep('upload'); }}>
                <RotateCcw className="w-4 h-4 mr-2" />
                Retry
              </Button>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Results Dashboard ───────────────────────────────────────── */}
      {isDone && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-8 duration-700">
          {/* Top Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <MetricCard label="Logs Classified" value={classification?.totalLogsRepresented?.toLocaleString() || '—'} colorClass="text-blue-400" icon={FileText} />
            <MetricCard label="Avg Confidence" value={`${classification?.summary?.averageConfidence || 0}%`} colorClass="text-emerald-400" icon={TrendingUp} />
            <MetricCard label="Timeline Events" value={timeline?.timeline?.length || '—'} colorClass="text-orange-400" icon={Activity} />
            <MetricCard label="RCA Confidence" value={`${rootCause?.analysis?.confidence || 0}%`} colorClass="text-red-400" icon={Shield} />
            <MetricCard label="Pipeline Time" value={`${(parseFloat(timings.classify || 0) + parseFloat(timings.timeline || 0) + parseFloat(timings.rootcause || 0)).toFixed(1)}s`} colorClass="text-orange-400" icon={Clock} />
            <MetricCard label="Engine" value="Local" colorClass="text-emerald-400" icon={Zap} />
          </div>

          {/* Main Tabs Area */}
          <Card className="bg-neutral-900 border-neutral-700 shadow-2xl overflow-hidden print:border-none print:shadow-none print:hidden">
            <Tabs defaultValue="classify" className="w-full">
              <div className="border-b border-neutral-700 p-4 md:px-6 bg-neutral-800/50 print:hidden">
                <TabsList className="bg-neutral-900/50 flex-wrap h-auto justify-start gap-1">
                  <TabsTrigger value="classify" className="data-[state=active]:bg-neutral-800 data-[state=active]:text-white text-neutral-400">
                    <Search className="w-4 h-4 mr-2" /> Classification
                  </TabsTrigger>
                  <TabsTrigger value="detection" className="data-[state=active]:bg-neutral-800 data-[state=active]:text-white text-neutral-400">
                    <Radar className="w-4 h-4 mr-2" /> Incidents
                  </TabsTrigger>
                  <TabsTrigger value="timeline" className="data-[state=active]:bg-neutral-800 data-[state=active]:text-white text-neutral-400">
                    <Activity className="w-4 h-4 mr-2" /> Timeline
                  </TabsTrigger>
                  <TabsTrigger value="rootcause" className="data-[state=active]:bg-neutral-800 data-[state=active]:text-white text-neutral-400">
                    <AlertTriangle className="w-4 h-4 mr-2" /> Root Cause
                  </TabsTrigger>
                  <TabsTrigger value="metrics" className="data-[state=active]:bg-neutral-800 data-[state=active]:text-white text-neutral-400">
                    <BarChart3 className="w-4 h-4 mr-2" /> Metrics
                  </TabsTrigger>
                </TabsList>
              </div>

              <div className="p-6 print:space-y-16 print:p-0">
                {/* ── Classification Panel ───────────────────────── */}
                <TabsContent value="classify" className="space-y-6 mt-0">
                  <div className="flex items-center gap-3 flex-wrap">
                    <CheckCircle className="w-6 h-6 text-emerald-400" />
                    <h2 className="text-xl font-bold text-white">Log Classification</h2>
                    <Badge variant="outline" className="border-neutral-700 text-neutral-400">{timings.classify}s</Badge>
                    {classification?.totalLogsRepresented && (
                      <Badge variant="secondary" className="text-neutral-400">
                        {classification.totalLogsRepresented.toLocaleString()} logs across {classification.totalClassified} patterns
                      </Badge>
                    )}
                  </div>

                  {classification?.categoryDistribution?.length > 0 && (
                    <div className="flex flex-col md:flex-row items-center gap-8 bg-neutral-800/30 rounded-xl p-6 border border-neutral-700">
                      <PieChart data={classification.categoryDistribution} size={240} />
                      <div className="flex-1">
                        <h3 className="font-semibold text-white mb-4">Category Distribution</h3>
                        <PieLegend data={classification.categoryDistribution} />
                      </div>
                    </div>
                  )}

                  {classification?.categoryDistribution?.length > 0 && (
                    <div className="space-y-3">
                      <h3 className="font-semibold text-white">Category Breakdown</h3>
                      <div className="overflow-x-auto rounded-lg border border-neutral-700">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="bg-neutral-800/60 text-neutral-400 text-left">
                              <th className="px-4 py-3 font-medium">Category</th>
                              <th className="px-4 py-3 font-medium text-right">Logs</th>
                              <th className="px-4 py-3 font-medium text-right">Patterns</th>
                              <th className="px-4 py-3 font-medium text-right">Share</th>
                              <th className="px-4 py-3 font-medium">Severity</th>
                              <th className="px-4 py-3 font-medium w-[40%]">Insight</th>
                            </tr>
                          </thead>
                          <tbody>
                            {classification.categoryDistribution
                              .map((cat, i) => (
                                <tr key={i} className="border-t border-neutral-700/50 hover:bg-neutral-800/30 transition-colors">
                                <td className="px-4 py-3">
                                  <div className="flex items-center gap-2">
                                    <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: getCategoryColor(cat.category) }} />
                                    <span className="text-white font-medium">{cat.category}</span>
                                  </div>
                                </td>
                                <td className="px-4 py-3 text-right text-neutral-300 tabular-nums">{cat.logCount.toLocaleString()}</td>
                                <td className="px-4 py-3 text-right text-neutral-400 tabular-nums">{cat.patternCount}</td>
                                <td className="px-4 py-3 text-right">
                                  <div className="flex items-center justify-end gap-2">
                                    <div className="w-16 h-1.5 bg-neutral-800 rounded-full overflow-hidden">
                                      <div className="h-full rounded-full" style={{ width: `${Math.min(cat.percentage, 100)}%`, background: getCategoryColor(cat.category) }} />
                                    </div>
                                    <span className="text-neutral-400 tabular-nums text-xs w-10 text-right">{cat.percentage}%</span>
                                  </div>
                                </td>
                                <td className="px-4 py-3">
                                  <Badge variant={
                                    cat.dominantSeverity === 'critical' ? 'destructive' :
                                      cat.dominantSeverity === 'high' ? 'warning' :
                                        'secondary'
                                  } className="text-[10px] px-1.5 py-0">
                                    {cat.dominantSeverity?.toUpperCase()}
                                  </Badge>
                                </td>
                                <td className="px-4 py-3 text-xs text-neutral-400 text-balance" title={cat.insight}>
                                  {cat.insight || '—'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  <div className="space-y-3">
                    <h3 className="font-semibold text-white">Detailed Pattern Classifications</h3>
                    {classification?.classifications?.map((cls, i) => (
                      <Card key={i} className="bg-neutral-800/50 border-neutral-700">
                        <CardContent className="p-4">
                          <div className="flex items-center gap-2 mb-2 flex-wrap">
                            <Badge variant={cls.sourceLevel === 'error' ? 'destructive' : 'secondary'}>
                              {cls.sourceLevel?.toUpperCase()}
                            </Badge>
                            <Badge variant="default" style={{ background: getCategoryColor(cls.classification?.category) + '33', color: getCategoryColor(cls.classification?.category), borderColor: getCategoryColor(cls.classification?.category) + '55' }} className="border">
                              {cls.classification?.category}
                            </Badge>
                            {cls.classification?.severity && (
                              <Badge variant={
                                cls.classification.severity === 'critical' ? 'destructive' :
                                  cls.classification.severity === 'high' ? 'warning' :
                                    'secondary'
                              } className="text-[10px] px-1.5 py-0">
                                {cls.classification.severity.toUpperCase()}
                              </Badge>
                            )}
                            <span className="text-xs text-neutral-400 font-mono ml-auto flex items-center gap-3">
                              {cls.occurrenceCount > 1 && <span className="text-neutral-400">×{cls.occurrenceCount.toLocaleString()}</span>}
                              Conf: {cls.classification?.confidence}%
                            </span>
                          </div>
                          <p className="text-xs text-neutral-400 font-mono bg-black/40 p-2 rounded border border-neutral-700 mb-3 overflow-x-auto">
                            {cls.originalLog}
                          </p>
                          <p className="text-sm text-neutral-300 leading-relaxed">
                            {cls.classification?.explanation}
                          </p>
                          {cls.classification?.insight && (
                            <p className="text-xs text-orange-300/70 mt-2 italic">
                              💡 {cls.classification.insight}
                            </p>
                          )}
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </TabsContent>

                {/* ── Incidents Panel ───────────────────────────── */}
                <TabsContent value="detection" className="space-y-6 mt-0">
                  <IncidentsPanel incidents={incidents} />
                </TabsContent>

                {/* ── Timeline Panel ─────────────────────────────── */}
                <TabsContent value="timeline" className="space-y-6 mt-0">
                  <TimelinePanel timeline={timeline} timings={timings} />
                </TabsContent>

                {/* ── Root Cause Panel ───────────────────────────── */}
                <TabsContent value="rootcause" className="space-y-6 mt-0">
                  <RootCausePanel rootCause={rootCause} timings={timings} />
                </TabsContent>

                {/* ── Metrics Panel ──────────────────────────────── */}
                <TabsContent value="metrics" className="space-y-6 mt-0">
                  <div className="flex items-center gap-3">
                    <BarChart3 className="w-6 h-6 text-orange-400" />
                    <h2 className="text-xl font-bold text-white">Performance Metrics</h2>
                  </div>

                  <Card className="bg-neutral-800/50 border-neutral-700">
                    <CardHeader>
                      <CardTitle className="text-lg">Local Analysis Engine</CardTitle>
                      <CardDescription>
                        All analysis runs locally on a trained TF-IDF + logistic-regression classifier and deterministic rules — no LLM API, no tokens, no keys required.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex justify-between items-center border-b border-neutral-700 pb-2">
                        <span className="text-sm text-neutral-400">Engine</span>
                        <span className="text-sm font-bold text-emerald-400">Local (trained model + rules)</span>
                      </div>
                      <div className="flex justify-between items-center border-b border-neutral-700 pb-2">
                        <span className="text-sm text-neutral-400">Classification</span>
                        <span className="text-sm font-bold text-emerald-400">{classification?.processingTimeMs || '—'}ms</span>
                      </div>
                      <div className="flex justify-between items-center border-b border-neutral-700 pb-2">
                        <span className="text-sm text-neutral-400">Incident Detection</span>
                        <span className="text-sm font-bold text-emerald-400">{incidents?.processingTimeMs || '—'}ms</span>
                      </div>
                      <div className="flex justify-between items-center border-b border-neutral-700 pb-2">
                        <span className="text-sm text-neutral-400">Timeline</span>
                        <span className="text-sm font-bold text-emerald-400">{timeline?.processingTimeMs || '—'}ms</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-neutral-400">Root Cause Analysis</span>
                        <span className="text-sm font-bold text-emerald-400">{rootCause?.processingTimeMs || '—'}ms</span>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-neutral-800/50 border-neutral-700 mt-6">
                    <CardHeader>
                      <CardTitle className="text-white flex items-center gap-2">
                        <Zap className="w-5 h-5 text-orange-400" /> Engine Usage
                      </CardTitle>
                      <CardDescription>
                        All pipeline stages run on the local engine — token/LLM usage is zero.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="overflow-x-auto rounded-lg border border-neutral-700">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="bg-neutral-800/60 text-neutral-400 text-left">
                              <th className="px-4 py-3 font-medium">Stage</th>
                              <th className="px-4 py-3 font-medium text-right">Prompt Tokens</th>
                              <th className="px-4 py-3 font-medium text-right">Completion Tokens</th>
                              <th className="px-4 py-3 font-medium text-right text-white">Total Tokens</th>
                            </tr>
                          </thead>
                          <tbody>
                            {[
                              { name: 'Classification', usage: classification?.usage },
                              { name: 'Timeline Generation', usage: timeline?.usage },
                              { name: 'Root Cause Analysis', usage: rootCause?.usage }
                            ].map((stage, i) => (
                              <tr key={i} className="border-t border-neutral-700/50 hover:bg-neutral-800/30">
                                <td className="px-4 py-3 font-medium text-neutral-300">{stage.name}</td>
                                <td className="px-4 py-3 text-right text-neutral-400 tabular-nums">{(stage.usage?.promptTokenCount || 0).toLocaleString()}</td>
                                <td className="px-4 py-3 text-right text-neutral-400 tabular-nums">{(stage.usage?.candidatesTokenCount || 0).toLocaleString()}</td>
                                <td className="px-4 py-3 text-right font-bold text-white tabular-nums">{(stage.usage?.totalTokenCount || 0).toLocaleString()}</td>
                              </tr>
                            ))}
                            <tr className="border-t-2 border-neutral-700 bg-neutral-800/30">
                              <td className="px-4 py-3 font-bold text-white">Pipeline Total</td>
                              <td className="px-4 py-3 text-right font-bold text-orange-400 tabular-nums">
                                {[classification, timeline, rootCause].reduce((acc, curr) => acc + (curr?.usage?.promptTokenCount || 0), 0).toLocaleString()}
                              </td>
                              <td className="px-4 py-3 text-right font-bold text-orange-400 tabular-nums">
                                {[classification, timeline, rootCause].reduce((acc, curr) => acc + (curr?.usage?.candidatesTokenCount || 0), 0).toLocaleString()}
                              </td>
                              <td className="px-4 py-3 text-right font-bold text-orange-400 tabular-nums">
                                {totalTokensUsed.toLocaleString()}
                              </td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>
              </div>
            </Tabs>
          </Card>

          {/* Print-only report (always in DOM, shown only on print) — 4 pages */}
          <div className="hidden print:block" aria-hidden="true">
            <h1 className="text-xl font-bold mb-1">Log Analysis Report</h1>
            <p className="text-xs text-neutral-400 mb-4">
              {new Date().toISOString().replace('T', ' ').slice(0, 19)} · Engine: local
            </p>

            {/* Page 1 — Classification */}
            <div className="print:page-break-after">
              <h2 className="text-lg font-semibold mb-3">1. Classification</h2>
              {classification && (
                <>
                  <p className="text-sm mb-3">
                    {classification.totalLogsRepresented?.toLocaleString()} logs across {classification.totalClassified} patterns
                  </p>
                  {classification.categoryDistribution?.length > 0 && (
                    <>
                      <h3 className="font-semibold mb-2">Category Distribution</h3>
                      <div className="flex flex-row items-start gap-6 mb-4">
                        <PieChart data={classification.categoryDistribution} size={240} />
                        <PieLegend data={classification.categoryDistribution} />
                      </div>
                      <table className="w-full text-sm">
                      <thead>
                        <tr className="bg-gray-100 text-left">
                          <th className="border border-gray-300 px-3 py-2 font-semibold">Category</th>
                          <th className="border border-gray-300 px-3 py-2 font-semibold text-right">Logs</th>
                          <th className="border border-gray-300 px-3 py-2 font-semibold text-right">Patterns</th>
                          <th className="border border-gray-300 px-3 py-2 font-semibold text-right">Share</th>
                          <th className="border border-gray-300 px-3 py-2 font-semibold">Severity</th>
                          <th className="border border-gray-300 px-3 py-2 font-semibold">Insight</th>
                        </tr>
                      </thead>
                      <tbody>
                        {classification.categoryDistribution
                          .map((cat, i) => (
                            <tr key={i}>
                              <td className="border border-gray-300 px-3 py-2 font-medium">{cat.category}</td>
                              <td className="border border-gray-300 px-3 py-2 text-right">{cat.logCount?.toLocaleString()}</td>
                              <td className="border border-gray-300 px-3 py-2 text-right">{cat.patternCount}</td>
                              <td className="border border-gray-300 px-3 py-2 text-right">{cat.percentage}%</td>
                              <td className="border border-gray-300 px-3 py-2">{cat.dominantSeverity?.toUpperCase() || '—'}</td>
                              <td className="border border-gray-300 px-3 py-2 text-xs">{cat.insight || '—'}</td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                    </>
                  )}
                </>
              )}
            </div>

            {/* Page 2 — Incidents */}
            <div className="print:page-break-after">
              <IncidentsPanel incidents={incidents} />
            </div>

            {/* Page 3 — Timeline */}
            <div className="print:page-break-after">
              <TimelinePanel timeline={timeline} timings={timings} />
            </div>

            {/* Page 4 — Root Cause */}
            <div>
              <RootCausePanel rootCause={rootCause} timings={timings} />
            </div>
          </div>

          <div className="flex justify-center pt-8 print:hidden">
            <Button variant="outline" className="border-neutral-700 text-neutral-300 hover:bg-neutral-800 hover:text-white" onClick={() => { setStepStatus({}); setCurrentStep('upload'); setClassification(null); setTimeline(null); setRootCause(null); setIncidents(null); }}>
              <RotateCcw className="w-4 h-4 mr-2" />
              Upload New Log File
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
