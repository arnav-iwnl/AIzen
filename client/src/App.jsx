import React, { useState, useEffect, useCallback } from 'react';
import {
  Upload, Play, CheckCircle, AlertTriangle, Activity,
  Clock, Shield, Zap, BarChart3, RotateCcw, FileText,
  TrendingUp, Search, Loader2, Download
} from 'lucide-react';
import {
  Button, Badge, Card, CardHeader, CardTitle,
  CardDescription, CardContent, Tabs, TabsList,
  TabsTrigger, TabsContent
} from './components/ui';
import {
  checkHealth, classifyLogs, generateTimeline, analyzeRootCause, uploadLogFile
} from './api';

// ── Pipeline Stepper ─────────────────────────────────────────────────────────
function PipelineStepper({ currentStep, stepStatus }) {
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

        let bgClass = "bg-transparent border-gray-800";
        let iconBg = "bg-gray-800 text-gray-400";
        let textClass = "text-gray-400";

        if (isActive) {
          bgClass = "bg-purple-900/20 border-purple-600";
          iconBg = "bg-purple-600 text-white";
          textClass = "text-purple-300";
        } else if (isDone) {
          bgClass = "bg-green-900/20 border-green-500";
          iconBg = "bg-green-500 text-white";
          textClass = "text-green-400";
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
              <div className={`w-0.5 h-6 md:w-8 md:h-0.5 ml-7 md:ml-0 transition-colors duration-300 ${isDone ? 'bg-green-500' : 'bg-gray-800'}`} />
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
    <Card className="bg-white/5 border-white/10">
      <CardContent className="p-4 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">{label}</span>
          {MetricIcon && <MetricIcon className={`w-4 h-4 ${colorClass}`} />}
        </div>
        <div className={`text-3xl font-bold ${colorClass}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

// ── Category Colors ──────────────────────────────────────────────────────
const CATEGORY_COLORS = {
  'Startup': '#22d3ee', // cyan
  'Shutdown': '#a78bfa', // violet
  'Configuration': '#60a5fa', // blue
  'Module Lifecycle': '#818cf8', // indigo
  'Worker Management': '#34d399', // emerald
  'Request Processing': '#2dd4bf', // teal
  'Client Error (4xx)': '#fb923c', // orange
  'Server Error (5xx)': '#f87171', // red
  'Resource Not Found': '#fbbf24', // amber
  'Backend Communication': '#38bdf8', // sky
  'Performance': '#e879f9', // fuchsia
  'Security': '#f43f5e', // rose
  'Network': '#4ade80', // green
  'Warning': '#facc15', // yellow
  'Unknown': '#94a3b8', // slate
  // Fallbacks for any AI-invented categories
  'Error': '#ef4444',
  'Worker Initialization': '#34d399',
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

  // Compute arcs
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
      {/* Visual Pie Chart */}
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
        {/* Center label */}
        <text x={cx} y={cy - 8} textAnchor="middle" fill="#fff" fontSize="22" fontWeight="bold" aria-hidden="true">
          {total.toLocaleString()}
        </text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill="#9ca3af" fontSize="11" aria-hidden="true">
          total logs
        </text>
      </svg>

      {/* Tooltip */}
      {hovered !== null && arcs[hovered] && (
        <div className="absolute z-20 pointer-events-none bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 shadow-xl text-xs"
          style={{ top: '50%', left: '50%', transform: 'translate(-50%, -130%)' }}
          aria-hidden="true"
        >
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: getCategoryColor(arcs[hovered].category) }} />
            <span className="font-bold text-white">{arcs[hovered].category}</span>
          </div>
          <div className="text-gray-300">
            {arcs[hovered].logCount.toLocaleString()} logs ({arcs[hovered].percentage}%)
          </div>
          <div className="text-gray-400 mt-0.5">
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
          <span className="text-gray-300 truncate">{d.category}</span>
          <span className="text-gray-400 ml-auto tabular-nums">{d.percentage}%</span>
        </div>
      ))}
    </div>
  );
}

// ── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [health, setHealth] = useState(null);
  const [stepStatus, setStepStatus] = useState({});
  const [currentStep, setCurrentStep] = useState('upload');
  const [classification, setClassification] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [rootCause, setRootCause] = useState(null);
  const [error, setError] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [timings, setTimings] = useState({});
  const [isPrinting, setIsPrinting] = useState(false);
  const [selectedModel, setSelectedModel] = useState('gemini-2.5-flash');

  const handleExportPDF = () => {
    setIsPrinting(true);
    setTimeout(() => {
      window.print();
      setIsPrinting(false);
    }, 100);
  };

  useEffect(() => {
    checkHealth()
      .then(d => setHealth(d))
      .catch(() => setHealth({ status: 'error' }));
  }, []);

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
    setTimings({});

    try {
      // Step 1: Upload
      setStep('upload', 'active');
      if (file) {
        await uploadLogFile(file);
      }
      setStep('upload', 'done');

      // Step 2: Classify
      setStep('classify', 'active');
      const t1 = Date.now();
      const classRes = await classifyLogs(null, selectedModel); // Backend will sample 5 logs from LogStore
      const classTime = ((Date.now() - t1) / 1000).toFixed(1);
      setClassification(classRes.data);
      setTimings(prev => ({ ...prev, classify: classTime }));
      setStep('classify', 'done');

      // Step 3: Timeline
      setStep('timeline', 'active');
      const t2 = Date.now();
      const timeRes = await generateTimeline({ focus: 'errors', maxEvents: 8, model: selectedModel });
      const timeTime = ((Date.now() - t2) / 1000).toFixed(1);
      setTimeline(timeRes.data);
      setTimings(prev => ({ ...prev, timeline: timeTime }));
      setStep('timeline', 'done');

      // Step 4: Root Cause
      setStep('rootcause', 'active');
      const t3 = Date.now();
      // Root cause analyzes the dominant category found in classification, or falls back to a generic symptom
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

  const isRunning = Object.values(stepStatus).includes('active');
  const isDone = stepStatus.rootcause === 'done';
  const totalTokensUsed = (classification?.usage?.totalTokenCount || 0) +
    (timeline?.usage?.totalTokenCount || 0) +
    (rootCause?.usage?.totalTokenCount || 0);

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-gray-100 font-sans selection:bg-purple-900/50">
      <a href="#main-content" className="sr-only focus:not-sr-only focus:absolute focus:p-4 focus:bg-purple-900 focus:text-white z-50">
        Skip to main content
      </a>
      <div className="max-w-6xl mx-auto p-6 space-y-8">

        {/* ── Header ──────────────────────────────────────────────────── */}
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-white rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(255,255,255,0.1)]">
              <Zap className="w-6 h-6 text-black" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white">AIzen</h1>
              <p className="text-sm text-gray-400 font-medium">Log Intelligence Engine</p>
            </div>
          </div>
          <div className="flex items-center gap-4">

            {isDone && (
              <Button variant="outline" size="sm" className="border-gray-700 text-gray-300 hover:bg-gray-800 hover:text-white print:hidden" onClick={handleExportPDF}>
                <Download className="w-4 h-4 mr-2" />
                Export PDF
              </Button>
            )}
            <Badge variant={health?.data?.status === 'healthy' ? 'success' : 'destructive'} className="shadow-sm">
              {health?.data?.status === 'healthy' ? 'Backend Online' : 'Backend Offline'}
            </Badge>
          </div>
        </header>

        <main id="main-content" className="space-y-8 focus:outline-none" tabIndex={-1}>
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
                className={`border-2 border-dashed rounded-2xl p-6 md:p-16 text-center cursor-pointer transition-all duration-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-900 ${isDragging ? 'border-purple-500 bg-purple-500/10 scale-[1.02]' : 'border-gray-800 bg-gray-900/50 hover:border-purple-500/50 hover:bg-gray-900'
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
                  <div className="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center">
                    <Upload className="w-8 h-8 text-purple-400" />
                  </div>
                  <h2 className="text-xl font-bold text-white">Upload Server Logs</h2>
                  <p className="text-sm text-gray-400 text-balance leading-relaxed">
                    Drag & drop your .log file here, or click to browse.
                    AIzen will classify errors, build an incident timeline, and identify the root cause instantly.
                  </p>

                  <div className="w-full mt-2 text-left" onClick={(e) => e.stopPropagation()}>
                    <label htmlFor="landing-model-select" className="block text-sm font-medium text-gray-400 mb-2">
                      Select Analysis Model
                    </label>
                    <select
                      id="landing-model-select"
                      value={selectedModel}
                      onChange={(e) => setSelectedModel(e.target.value)}
                      disabled={isRunning}
                      className="bg-gray-900 border border-gray-700 text-gray-300 text-sm rounded-lg focus:ring-purple-500 focus:border-purple-500 block w-full p-2.5"
                    >
                      <option value="gemini-2.5-flash">Google Gemini 2.5 Flash</option>
                      <option value="mistralai/mistral-small-4-119b-2603">Mistral 4</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-4 w-full py-4">
                    <div className="h-px bg-gray-800 flex-1" />
                    <span className="text-xs text-gray-600 font-medium uppercase tracking-wider">or</span>
                    <div className="h-px bg-gray-800 flex-1" />
                  </div>
                  <Button
                    variant="secondary"
                    className="w-full bg-white/10 hover:bg-white/20 text-white"
                    onClick={(e) => { e.stopPropagation(); runPipeline(null); }}
                  >
                    <Play className="w-4 h-4 mr-2" />
                    Use Pre-loaded Apache Logs
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* ── Loading State ───────────────────────────────────────────── */}
          {isRunning && (
            <div className="animate-in fade-in zoom-in-95 duration-300">
              <Card className="bg-gray-900/50 border-gray-800 py-8 md:py-16 px-2 md:px-0" aria-live="polite" aria-busy="true">
                <CardContent className="flex flex-col items-center justify-center gap-6">
                  <div className="relative">
                    <div className="absolute inset-0 bg-purple-500/20 blur-xl rounded-full" />
                    <Loader2 className="w-12 h-12 text-purple-400 animate-spin relative" />
                  </div>
                  <div className="text-center space-y-2">
                    <h3 className="text-lg md:text-xl font-bold text-white text-balance px-4">
                      {currentStep === 'upload' && 'Ingesting & parsing logs...'}
                      {currentStep === 'classify' && 'AI is classifying log entries...'}
                      {currentStep === 'timeline' && 'Generating incident timeline...'}
                      {currentStep === 'rootcause' && 'Analyzing root cause & recovery...'}
                    </h3>
                    <p className="text-sm text-gray-400 animate-pulse">
                      This typically takes 10-30 seconds per phase.
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
                <MetricCard label="Total Pipeline Time" value={`${(parseFloat(timings.classify || 0) + parseFloat(timings.timeline || 0) + parseFloat(timings.rootcause || 0)).toFixed(1)}s`} colorClass="text-purple-400" icon={Clock} />
                <MetricCard label="Total Tokens" value={totalTokensUsed.toLocaleString()} colorClass="text-purple-400" icon={Zap} />
              </div>

              {/* Main Tabs Area */}
              <Card className="bg-[#0f0f11] border-gray-800 shadow-2xl overflow-hidden print:border-none print:shadow-none">
                <Tabs defaultValue="classify" className="w-full">
                  <div className="border-b border-gray-800 p-4 md:px-6 bg-gray-900/20 print:hidden">
                    <TabsList className="bg-gray-900/50 flex-wrap h-auto justify-start gap-1">
                      <TabsTrigger value="classify" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400">
                        <Search className="w-4 h-4 mr-2" /> Classification
                      </TabsTrigger>
                      <TabsTrigger value="timeline" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400">
                        <Activity className="w-4 h-4 mr-2" /> Timeline
                      </TabsTrigger>
                      <TabsTrigger value="rootcause" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400">
                        <AlertTriangle className="w-4 h-4 mr-2" /> Root Cause
                      </TabsTrigger>
                      <TabsTrigger value="metrics" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400">
                        <BarChart3 className="w-4 h-4 mr-2" /> Metrics
                      </TabsTrigger>
                    </TabsList>
                  </div>

                  <div className="p-6 print:space-y-16 print:p-0">
                    {/* ── Classification Panel ───────────────────────── */}
                    <TabsContent value="classify" forceMount={isPrinting ? true : undefined} className={`space-y-6 mt-0 ${isPrinting ? 'print:block' : ''}`}>
                      <div className="flex items-center gap-3">
                        <CheckCircle className="w-6 h-6 text-emerald-400" />
                        <h2 className="text-xl font-bold text-white">Log Classification</h2>
                        <Badge variant="outline" className="border-gray-700 text-gray-400">{timings.classify}s</Badge>
                        {classification?.totalLogsRepresented && (
                          <Badge variant="secondary" className="text-gray-400">
                            {classification.totalLogsRepresented.toLocaleString()} logs across {classification.totalClassified} patterns
                          </Badge>
                        )}
                      </div>

                      {/* Pie Chart + Legend row */}
                      {classification?.categoryDistribution?.length > 0 && (
                        <div className="flex flex-col md:flex-row items-center gap-8 bg-gray-900/30 rounded-xl p-6 border border-gray-800">
                          <PieChart data={classification.categoryDistribution} size={240} />
                          <div className="flex-1">
                            <h3 className="font-semibold text-white mb-4">Category Distribution</h3>
                            <PieLegend data={classification.categoryDistribution} />
                          </div>
                        </div>
                      )}

                      {/* Category Summary Table */}
                      {classification?.categoryDistribution?.length > 0 && (
                        <div className="space-y-3">
                          <h3 className="font-semibold text-white">Category Breakdown</h3>
                          <div className="overflow-x-auto rounded-lg border border-gray-800">
                            <table className="w-full text-sm">
                              <thead>
                                <tr className="bg-gray-900/60 text-gray-400 text-left">
                                  <th className="px-4 py-3 font-medium">Category</th>
                                  <th className="px-4 py-3 font-medium text-right">Logs</th>
                                  <th className="px-4 py-3 font-medium text-right">Patterns</th>
                                  <th className="px-4 py-3 font-medium text-right">Share</th>
                                  <th className="px-4 py-3 font-medium">Severity</th>
                                  <th className="px-4 py-3 font-medium w-[40%]">Insight</th>
                                </tr>
                              </thead>
                              <tbody>
                                {classification.categoryDistribution.map((cat, i) => (
                                  <tr key={i} className="border-t border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                                    <td className="px-4 py-3">
                                      <div className="flex items-center gap-2">
                                        <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: getCategoryColor(cat.category) }} />
                                        <span className="text-white font-medium">{cat.category}</span>
                                      </div>
                                    </td>
                                    <td className="px-4 py-3 text-right text-gray-300 tabular-nums">{cat.logCount.toLocaleString()}</td>
                                    <td className="px-4 py-3 text-right text-gray-400 tabular-nums">{cat.patternCount}</td>
                                    <td className="px-4 py-3 text-right">
                                      <div className="flex items-center justify-end gap-2">
                                        <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                          <div className="h-full rounded-full" style={{ width: `${Math.min(cat.percentage, 100)}%`, background: getCategoryColor(cat.category) }} />
                                        </div>
                                        <span className="text-gray-400 tabular-nums text-xs w-10 text-right">{cat.percentage}%</span>
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
                                    <td className="px-4 py-3 text-xs text-gray-400 text-balance" title={cat.insight}>
                                      {cat.insight || '—'}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* Detailed Classification Cards (grouped by category) */}
                      <div className="space-y-3">
                        <h3 className="font-semibold text-white">Detailed Pattern Classifications</h3>
                        {classification?.classifications?.map((cls, i) => (
                          <Card key={i} className="bg-gray-900/50 border-gray-800">
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
                                <span className="text-xs text-gray-400 font-mono ml-auto flex items-center gap-3">
                                  {cls.occurrenceCount > 1 && <span className="text-gray-400">×{cls.occurrenceCount.toLocaleString()}</span>}
                                  Conf: {cls.classification?.confidence}%
                                </span>
                              </div>
                              <p className="text-xs text-gray-400 font-mono bg-black/40 p-2 rounded border border-gray-800 mb-3 overflow-x-auto">
                                {cls.originalLog}
                              </p>
                              <p className="text-sm text-gray-300 leading-relaxed">
                                {cls.classification?.explanation}
                              </p>
                              {cls.classification?.insight && (
                                <p className="text-xs text-purple-300/70 mt-2 italic">
                                  💡 {cls.classification.insight}
                                </p>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </TabsContent>

                    {/* ── Timeline Panel ─────────────────────────────── */}
                    <TabsContent value="timeline" forceMount={isPrinting ? true : undefined} className={`space-y-6 mt-0 ${isPrinting ? 'print:block' : ''}`}>
                      <div className="flex items-center gap-3">
                        <Activity className="w-6 h-6 text-blue-400" />
                        <h2 className="text-xl font-bold text-white">Incident Timeline</h2>
                        <Badge variant="outline" className="border-gray-700 text-gray-400">{timings.timeline}s</Badge>
                      </div>

                      {timeline?.overallSummary && (
                        <Card className="bg-blue-500/10 border-blue-500/20">
                          <CardContent className="p-4">
                            <p className="text-sm text-blue-100">{timeline.overallSummary}</p>
                          </CardContent>
                        </Card>
                      )}

                      <div className="pl-4 border-l-2 border-gray-800 space-y-8 mt-8">
                        {timeline?.timeline?.map((event, idx) => (
                          <div className="relative" key={idx}>
                            <div className={`absolute -left-[21px] top-1 w-3 h-3 rounded-full border-2 border-[#0f0f11] ${event.severity === 'critical' ? 'bg-red-500' :
                              event.severity === 'error' ? 'bg-orange-500' :
                                'bg-blue-500'
                              }`} />

                            <div className="flex items-center gap-2 mb-1">
                              <Badge variant={event.severity === 'critical' ? 'destructive' : event.severity === 'error' ? 'warning' : 'secondary'} className="text-[10px] px-1.5 py-0">
                                {event.severity?.toUpperCase()}
                              </Badge>
                              <span className="text-xs text-gray-400 font-mono">{event.timestamp}</span>
                            </div>

                            <h4 className="font-bold text-white mb-1">{event.eventTitle}</h4>
                            <p className="text-sm text-gray-400 mb-3">{event.summary}</p>

                            {event.supportingEvidence?.length > 0 && (
                              <div className="space-y-1 bg-gray-900/50 p-3 rounded-md border border-gray-800">
                                {event.supportingEvidence.map((ev, j) => (
                                  <p key={j} className="text-xs text-gray-400 font-mono truncate hover:whitespace-normal">
                                    → {ev}
                                  </p>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </TabsContent>

                    {/* ── Root Cause Panel ───────────────────────────── */}
                    <TabsContent value="rootcause" forceMount={isPrinting ? true : undefined} className={`space-y-6 mt-0 ${isPrinting ? 'print:block' : ''}`}>
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="w-6 h-6 text-red-500" />
                        <h2 className="text-xl font-bold text-white">Root Cause & Recovery</h2>
                        <Badge variant="outline" className="border-gray-700 text-gray-400">{timings.rootcause}s</Badge>
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
                                <div className="flex-shrink-0 w-6 h-6 rounded bg-gray-800 text-gray-400 flex items-center justify-center text-xs font-bold">
                                  {i + 1}
                                </div>
                                <p className="text-sm text-gray-300 pt-0.5">{step}</p>
                              </div>
                            ))}
                          </div>
                        </div>

                        <div className="space-y-4">
                          <h3 className="font-semibold text-white">System Impact</h3>
                          <p className="text-sm text-gray-400 leading-relaxed bg-gray-900/50 p-4 rounded-lg border border-gray-800">
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
                            <Card key={i} className="bg-gray-900/50 border-gray-800">
                              <CardContent className="p-4 flex gap-4">
                                <Badge variant={rec.priority === 'high' ? 'destructive' : rec.priority === 'medium' ? 'warning' : 'secondary'} className="h-fit">
                                  {rec.priority?.toUpperCase()}
                                </Badge>
                                <div>
                                  <h4 className="font-bold text-white text-sm mb-1">{rec.action}</h4>
                                  <p className="text-sm text-gray-400">{rec.rationale}</p>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </div>
                    </TabsContent>

                    {/* ── Metrics Panel ──────────────────────────────── */}
                    <TabsContent value="metrics" forceMount={isPrinting ? true : undefined} className={`space-y-6 mt-0 ${isPrinting ? 'print:block' : ''}`}>
                      <div className="flex items-center gap-3">
                        <BarChart3 className="w-6 h-6 text-purple-400" />
                        <h2 className="text-xl font-bold text-white">Performance Metrics</h2>
                      </div>

                      <Card className="bg-gray-900/50 border-gray-800">
                        <CardHeader>
                          <CardTitle className="text-lg">Context Selection Efficiency</CardTitle>
                          <CardDescription>
                            AIzen uses fingerprint deduplication, time-windowing, and stratified sampling to drastically reduce token usage while preserving reasoning capability.
                          </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="flex justify-between items-center border-b border-gray-800 pb-2">
                            <span className="text-sm text-gray-400">Raw log file</span>
                            <span className="text-sm font-bold text-white">~180 KB (2,000 lines)</span>
                          </div>
                          <div className="flex justify-between items-center border-b border-gray-800 pb-2">
                            <span className="text-sm text-gray-400">Classification Context</span>
                            <span className="text-sm font-bold text-emerald-400">~2 KB (5 logs + neighbors)</span>
                          </div>
                          <div className="flex justify-between items-center border-b border-gray-800 pb-2">
                            <span className="text-sm text-gray-400">Timeline Context</span>
                            <span className="text-sm font-bold text-emerald-400">~6 KB (33 deduplicated patterns)</span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-sm text-gray-400">Root Cause Context</span>
                            <span className="text-sm font-bold text-emerald-400">~11 KB (30 patterns + 60 samples)</span>
                          </div>
                        </CardContent>
                      </Card>

                      {/* ── Token Usage Table ───────────────────────────────── */}
                      <Card className="bg-gray-900/50 border-gray-800 mt-6">
                        <CardHeader>
                          <CardTitle className="text-white flex items-center gap-2">
                            <Zap className="w-5 h-5 text-purple-400" /> API Token Usage
                          </CardTitle>
                          <CardDescription>
                            Token consumption for Gemini API calls across pipeline stages.
                          </CardDescription>
                        </CardHeader>
                        <CardContent>
                          <div className="overflow-x-auto rounded-lg border border-gray-800">
                            <table className="w-full text-sm">
                              <thead>
                                <tr className="bg-gray-900/60 text-gray-400 text-left">
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
                                  <tr key={i} className="border-t border-gray-800/50 hover:bg-gray-800/30">
                                    <td className="px-4 py-3 font-medium text-gray-300">{stage.name}</td>
                                    <td className="px-4 py-3 text-right text-gray-400 tabular-nums">{(stage.usage?.promptTokenCount || 0).toLocaleString()}</td>
                                    <td className="px-4 py-3 text-right text-gray-400 tabular-nums">{(stage.usage?.candidatesTokenCount || 0).toLocaleString()}</td>
                                    <td className="px-4 py-3 text-right font-bold text-white tabular-nums">{(stage.usage?.totalTokenCount || 0).toLocaleString()}</td>
                                  </tr>
                                ))}
                                <tr className="border-t-2 border-gray-700 bg-gray-900/30">
                                  <td className="px-4 py-3 font-bold text-white">Pipeline Total</td>
                                  <td className="px-4 py-3 text-right font-bold text-purple-400 tabular-nums">
                                    {[classification, timeline, rootCause].reduce((acc, curr) => acc + (curr?.usage?.promptTokenCount || 0), 0).toLocaleString()}
                                  </td>
                                  <td className="px-4 py-3 text-right font-bold text-purple-400 tabular-nums">
                                    {[classification, timeline, rootCause].reduce((acc, curr) => acc + (curr?.usage?.candidatesTokenCount || 0), 0).toLocaleString()}
                                  </td>
                                  <td className="px-4 py-3 text-right font-bold text-purple-400 tabular-nums">
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

              <div className="flex justify-center pt-8 print:hidden">
                <Button variant="outline" className="border-gray-700 text-gray-300 hover:bg-gray-800 hover:text-white" onClick={() => { setStepStatus({}); setCurrentStep('upload'); setClassification(null); setTimeline(null); setRootCause(null); }}>
                  <RotateCcw className="w-4 h-4 mr-2" />
                  Upload New Log File
                </Button>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
