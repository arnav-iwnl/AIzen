import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Radio, Trash2, ShieldAlert, Activity, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import { Badge, Button, Card, CardContent } from '../components/ui';
import { openRealtimeStream, clearRealtime } from '../api';
import { addNotification } from '../notificationStore';

const LEVEL_VARIANT = {
  error: 'destructive', crit: 'destructive', critical: 'destructive', emerg: 'destructive',
  warn: 'warning', warning: 'warning',
  info: 'secondary', notice: 'secondary', debug: 'secondary', unknown: 'outline',
};

const CATEGORY_COLORS = {
  Security: '#f43f5e', Error: '#ef4444', 'Backend Communication': '#38bdf8',
  Network: '#4ade80', Performance: '#e879f9', 'Service Instability': '#fb923c',
  'Resource Not Found': '#fbbf24', 'Request Processing': '#2dd4bf', Startup: '#22d3ee',
  Shutdown: '#a78bfa', Configuration: '#60a5fa', 'Worker Initialization': '#34d399',
  Warning: '#facc15', Unknown: '#94a3b8',
};

const MAX_RENDERED = 150;

function Metric({ label, value, colorClass, icon: Icon }) {
  return (
    <Card className="bg-neutral-900 border-neutral-700">
      <CardContent className="p-4 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-xs text-neutral-400 tracking-wider">{label}</span>
          {Icon && <Icon className={`w-4 h-4 ${colorClass}`} />}
        </div>
        <div className={`text-2xl font-bold font-mono ${colorClass}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

export default function RealtimeView() {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [counters, setCounters] = useState({ total: 0, errors: 0, warnings: 0, security: 0, categoryCounts: {} });
  const [connected, setConnected] = useState(false);
  const feedRef = useRef(null);
  const esRef = useRef(null);

  useEffect(() => {
    const es = openRealtimeStream(
      (payload) => {
        if (payload.type === 'snapshot') {
          setEvents(payload.events || []);
          setAlerts(payload.alerts || []);
          setCounters(payload.counters || counters);
        } else if (payload.type === 'log') {
          const ev = payload.event;
          setEvents((prev) => [...prev, ev]);
          setCounters((prev) => {
            const cats = { ...prev.categoryCounts };
            cats[ev.category] = (cats[ev.category] || 0) + 1;
            return {
              ...prev,
              total: prev.total + 1,
              errors: prev.errors + (['error', 'crit', 'critical', 'emerg', 'alert'].includes(ev.level) ? 1 : 0),
              warnings: prev.warnings + (['warn', 'warning'].includes(ev.level) ? 1 : 0),
              security: prev.security + (ev.securityTypes?.length ? 1 : 0),
              categoryCounts: cats,
            };
          });
        } else if (payload.type === 'alert') {
          setAlerts((prev) => [payload.alert, ...prev].slice(0, 20));
        } else if (payload.type === 'attack') {
          const ev = payload.event;
          toast.error(`${ev.v2Attack.toUpperCase()} attack detected`, {
            id: `attack-${ev.id}`,
            description: `${ev.confidence}% confidence \u2022 ${ev.message.slice(0, 80)}`,
            duration: 5000,
          });
          addNotification({
            type: ev.v2Attack,
            confidence: ev.confidence,
            message: ev.message,
            ts: ev.ts,
            level: ev.level,
            securityTypes: ev.securityTypes,
          });
        }
      },
      () => setConnected(false)
    );
    es.onopen = () => setConnected(true);
    esRef.current = es;
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-scroll feed
  useEffect(() => {
    const el = feedRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events]);

  const ratePerSec = useMemo(() => {
    const cutoff = Date.now() - 10000;
    const recent = events.filter((e) => new Date(e.ts).getTime() > cutoff).length;
    return (recent / 10).toFixed(1);
  }, [events]);

  const categoryBars = useMemo(() => {
    const total = Object.values(counters.categoryCounts).reduce((a, b) => a + b, 0);
    if (total === 0) return [];
    return Object.entries(counters.categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([cat, n]) => ({ cat, n, pct: Math.round((n / total) * 100) }));
  }, [counters.categoryCounts]);

  // Live activity series: events per second over the last 45s (total + errors).
  const activity = useMemo(() => {
    const BUCKETS = 45;
    const now = Date.now();
    const start = now - BUCKETS * 1000;
    const totals = new Array(BUCKETS).fill(0);
    const errors = new Array(BUCKETS).fill(0);
    events.forEach((e) => {
      const t = new Date(e.ts).getTime();
      const i = Math.floor((t - start) / 1000);
      if (i >= 0 && i < BUCKETS) {
        totals[i] += 1;
        if (['error', 'crit', 'critical', 'emerg', 'alert'].includes(e.level)) errors[i] += 1;
      }
    });
    const max = Math.max(1, ...totals);
    return { totals, errors, max };
  }, [events]);

  const activityPoints = useMemo(() => {
    const W = 1000, H = 150, PAD = 4;
    const x = (i) => (i / (activity.totals.length - 1)) * W;
    const y = (v) => H - PAD - (v / activity.max) * (H - PAD * 2);
    return {
      total: activity.totals.map((v, i) => `${x(i)},${y(v)}`).join(' '),
      error: activity.errors.map((v, i) => `${x(i)},${y(v)}`).join(' '),
    };
  }, [activity]);

  // Engine health derived from error rate (% of recent events that are errors).
  const healthPct = useMemo(() => {
    if (counters.total === 0) return 100;
    return Math.max(0, Math.round(100 - (counters.errors / counters.total) * 100));
  }, [counters]);

  const handleClear = async () => {
    try { await clearRealtime(); } catch { /* ignore */ }
    setEvents([]);
    setAlerts([]);
    setCounters({ total: 0, errors: 0, warnings: 0, security: 0, categoryCounts: {} });
  };

  const rendered = events.slice(-MAX_RENDERED);

  return (
    <div className="p-6 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-wider">REALTIME SIEM</h1>
          <p className="text-sm text-neutral-400">Live log stream — parsed, classified, and alerted locally</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`flex items-center gap-2 text-sm ${connected ? 'text-emerald-400' : 'text-neutral-500'}`}>
            <span className={`w-2.5 h-2.5 rounded-full animate-pulse ${connected ? 'bg-emerald-400' : 'bg-neutral-600'}`} />
            {connected ? 'LIVE' : 'DISCONNECTED'}
          </span>
          <Button variant="outline" size="sm" className="border-red-900/50 text-red-400 hover:bg-red-950/30" onClick={handleClear}>
            <Trash2 className="w-4 h-4 mr-2" /> Clear
          </Button>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <Metric label="Events" value={counters.total.toLocaleString()} colorClass="text-white" icon={Activity} />
        <Metric label="Errors" value={counters.errors.toLocaleString()} colorClass="text-red-500" icon={AlertTriangle} />
        <Metric label="Warnings" value={counters.warnings.toLocaleString()} colorClass="text-amber-500" icon={AlertTriangle} />
        <Metric label="Security Events" value={counters.security.toLocaleString()} colorClass="text-rose-500" icon={ShieldAlert} />
        <Metric label="Rate / sec" value={ratePerSec} colorClass="text-orange-500" icon={Radio} />
      </div>

      {/* Command-center style grid: Engine activity chart + live category distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Engine activity line chart (decorative, mirrors command-center) */}
        <Card className="lg:col-span-8 bg-neutral-900 border-neutral-700">
          <CardContent className="p-5">
            <p className="text-sm font-medium text-neutral-300 tracking-wider mb-4">ENGINE ACTIVITY OVERVIEW</p>
            <div className="h-48 relative">
              <div className="absolute inset-0 grid grid-cols-8 grid-rows-6 opacity-20">
                {Array.from({ length: 48 }).map((_, i) => (
                  <div key={i} className="border border-neutral-700"></div>
                ))}
              </div>
              <svg className="absolute inset-0 w-full h-full" preserveAspectRatio="none" viewBox="0 0 1000 150">
                <polyline
                  points={activityPoints.total}
                  fill="none"
                  stroke="#ffffff"
                  strokeWidth="2"
                  strokeDasharray="5,5"
                  vectorEffect="non-scaling-stroke"
                />
                <polyline
                  points={activityPoints.error}
                  fill="none"
                  stroke="#f97316"
                  strokeWidth="2"
                  vectorEffect="non-scaling-stroke"
                />
              </svg>
              <div className="absolute left-0 top-0 h-full flex flex-col justify-between text-xs text-neutral-500 -ml-5 font-mono">
                <span>{activity.max}</span>
                <span>{Math.round(activity.max * 0.66)}</span>
                <span>{Math.round(activity.max * 0.33)}</span>
                <span>0</span>
              </div>
              <div className="absolute bottom-0 left-0 w-full flex justify-between text-xs text-neutral-500 -mb-6 font-mono">
                <span>45 SEC AGO</span>
                <span>NOW</span>
              </div>
            </div>
            <div className="flex items-center gap-4 mt-8 text-xs text-neutral-400">
              <span className="flex items-center gap-2">
                <span className="w-3 h-0.5 bg-white inline-block" /> Total events
              </span>
              <span className="flex items-center gap-2">
                <span className="w-3 h-0.5 bg-orange-500 inline-block" /> Errors
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Wireframe sphere status */}
        <Card className="lg:col-span-4 bg-neutral-900 border-neutral-700">
          <CardContent className="p-5 flex flex-col items-center">
            <p className="text-sm font-medium text-neutral-300 tracking-wider self-start mb-4">ENGINE STATUS</p>
            <div className="relative w-32 h-32 mb-4">
              <div className={`absolute inset-0 border-2 rounded-full opacity-60 animate-pulse ${connected ? 'border-emerald-500' : 'border-red-500'}`}></div>
              <div className="absolute inset-2 border border-neutral-400 rounded-full opacity-40"></div>
              <div className="absolute inset-4 border border-neutral-400 rounded-full opacity-20"></div>
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-full h-px bg-neutral-400 opacity-30"></div>
              </div>
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-px h-full bg-neutral-400 opacity-30"></div>
              </div>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className={`text-xl font-bold font-mono ${healthPct >= 85 ? 'text-emerald-400' : healthPct >= 60 ? 'text-orange-400' : 'text-red-500'}`}>
                  {healthPct}%
                </span>
              </div>
            </div>
            <div className="text-xs text-neutral-500 space-y-1 w-full font-mono">
              <div className="flex justify-between">
                <span>ENGINE:</span>
                <span className={connected ? 'text-emerald-400' : 'text-red-500'}>{connected ? 'ONLINE' : 'OFFLINE'}</span>
              </div>
              <div className="flex justify-between">
                <span>HEALTH:</span>
                <span className={`${healthPct >= 85 ? 'text-emerald-400' : healthPct >= 60 ? 'text-orange-400' : 'text-red-500'}`}>{healthPct}%</span>
              </div>
              <div className="flex justify-between">
                <span>EVENTS:</span>
                <span className="text-white">{counters.total.toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span>ERRORS:</span>
                <span className="text-red-500">{counters.errors.toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span>ALERTS:</span>
                <span className="text-orange-400">{alerts.length}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Category distribution */}
      {categoryBars.length > 0 && (
        <Card className="bg-neutral-900 border-neutral-700">
          <CardContent className="p-5">
            <p className="text-sm font-medium text-neutral-300 tracking-wider mb-3">CATEGORY DISTRIBUTION</p>
            <div className="space-y-2">
              {categoryBars.map(({ cat, n, pct }) => (
                <div key={cat} className="flex items-center gap-3">
                  <span className="text-xs text-neutral-400 w-40 truncate flex-shrink-0">{cat}</span>
                  <div className="flex-1 h-2 bg-neutral-800 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: CATEGORY_COLORS[cat] || '#94a3b8' }} />
                  </div>
                  <span className="text-xs text-neutral-500 tabular-nums w-16 text-right">{n.toLocaleString()} ({pct}%)</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Alerts (activity log style) */}
      {alerts.length > 0 && (
        <Card className="bg-neutral-900 border-neutral-700">
          <CardContent className="p-5">
            <p className="text-sm font-medium text-neutral-300 tracking-wider mb-3">ALERT STREAM</p>
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {alerts.slice(0, 10).map((a) => (
                <div key={a.id} className={`text-xs border-l-2 pl-3 p-2 rounded transition-colors ${a.severity === 'critical' ? 'border-red-500' : 'border-orange-500'}`}>
                  <div className="flex items-center gap-2">
                    <ShieldAlert className={`w-3 h-3 flex-shrink-0 ${a.severity === 'critical' ? 'text-red-500' : 'text-orange-400'}`} />
                    <span className={`text-sm font-bold text-white`}>{a.title}</span>
                    <span className="text-[10px] text-neutral-500 font-mono ml-auto">{new Date(a.ts).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-xs text-neutral-400 mt-1">{a.detail}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Live feed */}
      <Card className="bg-neutral-900 border-neutral-700 overflow-hidden">
        <div className="border-b border-neutral-700 px-4 py-2 flex items-center justify-between bg-neutral-800/50">
          <span className="text-sm font-semibold text-neutral-300 uppercase tracking-wider">Live Log Feed</span>
          <span className="text-xs text-neutral-500 font-mono">{events.length} buffered</span>
        </div>
        <div ref={feedRef} className="h-[420px] overflow-y-auto font-mono text-xs" style={{ scrollBehavior: 'smooth' }}>
          {rendered.length === 0 ? (
            <p className="text-neutral-600 p-6 text-center">Feed is empty. Fire demo actions from the Demo tab, or start the auto-stream.</p>
          ) : (
            rendered.map((e) => (
              <div key={e.id} className="flex items-start gap-2 px-4 py-1.5 border-b border-neutral-800/60 hover:bg-neutral-800/40 transition-colors">
                <span className="text-neutral-600 flex-shrink-0 w-16 tabular-nums">{new Date(e.ts).toLocaleTimeString('en-GB')}</span>
                <Badge variant={LEVEL_VARIANT[e.level] || 'outline'} className="text-[10px] px-1.5 py-0 w-16 justify-center flex-shrink-0 uppercase">
                  {e.level}
                </Badge>
                <span className="text-[10px] font-semibold text-neutral-300 flex-shrink-0 w-36 truncate">
                  {e.category}
                </span>
                <span className="flex-shrink-0 w-3 text-center">
                  {e.securityTypes?.length > 0 && <ShieldAlert className="w-3 h-3 text-rose-500 inline" />}
                </span>
                <span className="text-neutral-400 break-all whitespace-pre-wrap">{e.raw}</span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
