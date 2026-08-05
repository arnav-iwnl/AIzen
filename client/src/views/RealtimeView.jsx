import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Radio, Trash2, Pause, Play, ShieldAlert, Activity, AlertTriangle } from 'lucide-react';
import { Badge, Button, Card, CardContent } from '../components/ui';
import { openRealtimeStream, clearRealtime } from '../api';

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

function Metric({ label, value, color, icon: Icon }) {
  return (
    <Card className="bg-white/5 border-white/10">
      <CardContent className="p-4 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">{label}</span>
          {Icon && <Icon className={`w-4 h-4 ${color}`} />}
        </div>
        <div className={`text-2xl font-bold ${color}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

export default function RealtimeView() {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [counters, setCounters] = useState({ total: 0, errors: 0, warnings: 0, security: 0, categoryCounts: {} });
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
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
        }
      },
      () => setConnected(false)
    );
    es.onopen = () => setConnected(true);
    esRef.current = es;
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-scroll feed unless paused
  useEffect(() => {
    const el = feedRef.current;
    if (el && !paused) el.scrollTop = el.scrollHeight;
  }, [events, paused]);

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

  const handleClear = async () => {
    try { await clearRealtime(); } catch { /* ignore */ }
    setEvents([]);
    setAlerts([]);
    setCounters({ total: 0, errors: 0, warnings: 0, security: 0, categoryCounts: {} });
  };

  const rendered = events.slice(-MAX_RENDERED);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-fuchsia-500/20 rounded-full flex items-center justify-center">
            <Radio className="w-5 h-5 text-fuchsia-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Real-time SIEM</h1>
            <p className="text-sm text-gray-400">Live log stream — parsed, classified, and alerted locally</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`flex items-center gap-2 text-sm ${connected ? 'text-emerald-400' : 'text-gray-500'}`}>
            <span className={`w-2.5 h-2.5 rounded-full animate-pulse ${connected ? 'bg-emerald-400' : 'bg-gray-600'}`} />
            {connected ? 'Live' : 'Disconnected'}
          </span>
          <Button variant="outline" size="sm" className="border-gray-700 text-gray-300 hover:bg-gray-800" onClick={() => setPaused((p) => !p)}>
            {paused ? <Play className="w-4 h-4 mr-2" /> : <Pause className="w-4 h-4 mr-2" />}
            {paused ? 'Resume' : 'Pause'}
          </Button>
          <Button variant="outline" size="sm" className="border-red-900/50 text-red-400 hover:bg-red-950/30" onClick={handleClear}>
            <Trash2 className="w-4 h-4 mr-2" /> Clear
          </Button>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <Metric label="Events" value={counters.total.toLocaleString()} color="text-gray-200" icon={Activity} />
        <Metric label="Errors" value={counters.errors.toLocaleString()} color="text-red-400" icon={AlertTriangle} />
        <Metric label="Warnings" value={counters.warnings.toLocaleString()} color="text-amber-400" icon={AlertTriangle} />
        <Metric label="Security Events" value={counters.security.toLocaleString()} color="text-rose-400" icon={ShieldAlert} />
        <Metric label="Rate / sec" value={ratePerSec} color="text-fuchsia-400" icon={Radio} />
      </div>

      {/* Category distribution */}
      {categoryBars.length > 0 && (
        <Card className="bg-gray-900/50 border-gray-800">
          <CardContent className="p-4">
            <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold mb-3">Category Distribution</p>
            <div className="space-y-2">
              {categoryBars.map(({ cat, n, pct }) => (
                <div key={cat} className="flex items-center gap-3">
                  <span className="text-xs text-gray-400 w-40 truncate flex-shrink-0">{cat}</span>
                  <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: CATEGORY_COLORS[cat] || '#94a3b8' }} />
                  </div>
                  <span className="text-xs text-gray-500 tabular-nums w-16 text-right">{n.toLocaleString()} ({pct}%)</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Alerts */}
      {alerts.length > 0 && (
        <div className="space-y-2">
          {alerts.slice(0, 5).map((a) => (
            <Card key={a.id} className={`border ${a.severity === 'critical' ? 'border-red-800 bg-red-950/20' : 'border-orange-800 bg-orange-950/10'}`}>
              <CardContent className="p-3 flex gap-3 items-start">
                <ShieldAlert className={`w-5 h-5 mt-0.5 flex-shrink-0 ${a.severity === 'critical' ? 'text-red-500' : 'text-orange-400'}`} />
                <div>
                  <div className="flex items-center gap-2">
                    <Badge variant={a.severity === 'critical' ? 'destructive' : 'warning'} className="uppercase text-[10px]">{a.severity}</Badge>
                    <span className="text-sm font-bold text-white">{a.title}</span>
                    <span className="text-[10px] text-gray-500 font-mono ml-auto">{new Date(a.ts).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-xs text-gray-400 mt-1">{a.detail}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Live feed */}
      <Card className="bg-[#0d0d0f] border-gray-800 overflow-hidden">
        <div className="border-b border-gray-800 px-4 py-2 flex items-center justify-between bg-gray-900/30">
          <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Live Log Feed</span>
          <span className="text-xs text-gray-500 font-mono">{events.length} buffered</span>
        </div>
        <div ref={feedRef} className="h-[420px] overflow-y-auto font-mono text-xs" style={{ scrollBehavior: 'smooth' }}>
          {rendered.length === 0 ? (
            <p className="text-gray-600 p-6 text-center">Feed is empty. Fire demo actions from the Demo tab, or start the auto-stream.</p>
          ) : (
            rendered.map((e) => (
              <div key={e.id} className="flex items-start gap-2 px-4 py-1.5 border-b border-gray-900/60 hover:bg-gray-900/40 transition-colors">
                <span className="text-gray-600 flex-shrink-0 w-16 tabular-nums">{new Date(e.ts).toLocaleTimeString('en-GB')}</span>
                <Badge variant={LEVEL_VARIANT[e.level] || 'outline'} className="text-[10px] px-1.5 py-0 w-16 justify-center flex-shrink-0 uppercase">
                  {e.level}
                </Badge>
                <span className="text-[10px] font-semibold text-gray-300 flex-shrink-0 w-36 truncate">
                  {e.category}
                </span>
                <span className="flex-shrink-0 w-3 text-center">
                  {e.securityTypes?.length > 0 && <ShieldAlert className="w-3 h-3 text-rose-500 inline" />}
                </span>
                <span className="text-gray-400 break-all whitespace-pre-wrap">{e.raw}</span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
