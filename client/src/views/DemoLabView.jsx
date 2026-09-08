import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Play, Square, Radio, Zap, ShieldAlert, Activity, Database, Trash2, AlertTriangle,
} from 'lucide-react';
import { toast } from 'sonner';
import { Button, Card, CardContent } from '../components/ui';
import { openRealtimeStream, getDatasetDemoSources, triggerDatasetDemo, controlDatasetDemoStream, clearRealtime } from '../api';

const LEVEL_COLOR = {
  error: 'text-red-400', crit: 'text-red-400', critical: 'text-red-400', emerg: 'text-red-400',
  warn: 'text-amber-400', warning: 'text-amber-400',
  info: 'text-neutral-400', notice: 'text-neutral-300', unknown: 'text-neutral-500',
};

const MAX_RENDERED = 120;

function LiveRow({ ev }) {
  const time = useMemo(() => {
    const d = new Date(ev.ts);
    let h = d.getHours() % 12 || 12;
    const m = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${h}:${m}:${s} ${d.getHours() >= 12 ? 'PM' : 'AM'}`;
  }, [ev.ts]);

  const isSec = ev.category === 'Security' || (ev.securityTypes?.length > 0);

  return (
    <div className="grid grid-cols-[84px_52px_84px_1fr] gap-2 px-3 py-1.5 text-xs border-b border-neutral-800/60 hover:bg-neutral-800/30 items-center">
      <span className="text-neutral-500 font-mono">{time}</span>
      <span className={`font-mono font-semibold uppercase ${LEVEL_COLOR[ev.level] || 'text-neutral-400'}`}>
        {ev.level || 'info'}
      </span>
      <span className={`font-medium uppercase ${isSec ? 'text-rose-400' : 'text-cyan-400'}`}>
        {ev.category}
      </span>
      <span className="text-neutral-400 truncate" title={ev.raw}>{ev.message}</span>
    </div>
  );
}

export default function DemoLabView() {
  const [sources, setSources] = useState([{ id: 'mixed', label: 'Mixed (logs + datasets)' }]);
  const [source, setSource] = useState('mixed');
  const [count, setCount] = useState(50);
  const [rate, setRate] = useState(5);
  const [streaming, setStreaming] = useState(false);
  const [events, setEvents] = useState([]);
  const [counters, setCounters] = useState({ total: 0, security: 0, errors: 0 });
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const feedRef = useRef(null);

  // Load sources
  useEffect(() => {
    getDatasetDemoSources()
      .then((r) => { if (r.data?.length) setSources(r.data); })
      .catch(() => {});
  }, []);

  // Live SSE feed (same hub the whole app uses)
  useEffect(() => {
    const es = openRealtimeStream((payload) => {
      if (payload.type === 'snapshot') {
        setEvents(payload.events || []);
        setCounters(payload.counters || counters);
      } else if (payload.type === 'log') {
        const ev = payload.event;
        setEvents((prev) => {
          const next = [...prev, ev];
          return next.length > 400 ? next.slice(next.length - 400) : next;
        });
        setCounters((prev) => ({
          ...prev,
          total: prev.total + 1,
          security: prev.security + (ev.securityTypes?.length ? 1 : 0),
          errors: prev.errors + (['error', 'crit', 'critical', 'emerg', 'alert'].includes(ev.level) ? 1 : 0),
        }));
      } else if (payload.type === 'alert') {
        // roll into a toast for high-impact alerts
        toast.warning(payload.alert?.title || 'Security alert', { duration: 4000 });
      } else if (payload.type === 'attack') {
        const ev = payload.event;
        toast.error(`${ev.v2Attack?.toUpperCase() || 'Attack'} detected`, {
          description: `${ev.confidence}% confidence - ${(ev.message || '').slice(0, 70)}`,
          duration: 5000,
        });
        // addNotification is now global in App.jsx
      }
    }, () => setConnected(false));
    es.onopen = () => setConnected(true);
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-scroll feed
  useEffect(() => {
    const el = feedRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events]);

  const fire = async () => {
    setBusy(true);
    try {
      const res = await triggerDatasetDemo(count, source);
      toast.info(`Fired ${res.data?.generated ?? 0} lines (${res.data?.attacks ?? 0} breaches)`, { duration: 2500 });
    } finally {
      setBusy(false);
    }
  };

  const toggleStream = async () => {
    const next = !streaming;
    const res = await controlDatasetDemoStream({ running: next, source, rate });
    if (res.data) setStreaming(!!res.data.running);
  };

  const clear = async () => {
    await clearRealtime();
    setEvents([]);
    setCounters({ total: 0, security: 0, errors: 0 });
  };

  const visible = events.slice(-MAX_RENDERED);

  return (
    <div className="p-6 space-y-5 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-orange-500/20 rounded-full flex items-center justify-center">
            <Database className="w-5 h-5 text-orange-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Demo Lab</h1>
            <p className="text-sm text-neutral-400">
              Sniff live traffic from <span className="text-orange-400">data/ logs</span> and the{' '}
              <span className="text-orange-400">v2 training datasets</span> (HF + Kaggle)
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <span className={`flex items-center gap-1.5 ${connected ? 'text-emerald-400' : 'text-red-400'}`}>
            <Radio className={`w-4 h-4 ${connected ? 'animate-pulse' : ''}`} />
            {connected ? 'SNIFFING' : 'DISCONNECTED'}
          </span>
        </div>
      </div>

      {/* Control panel */}
      <Card className="bg-neutral-900 border-neutral-700">
        <CardContent className="p-5 flex flex-col md:flex-row md:items-end gap-4">
          <div className="flex-1 min-w-48">
            <label className="block text-sm text-neutral-400 mb-1.5">Traffic source</label>
            <select
              value={source}
              onChange={(e) => { setSource(e.target.value); setStreaming(false); if (streaming) controlDatasetDemoStream({ running: false }); }}
              className="bg-neutral-900 border border-neutral-700 text-neutral-300 text-sm rounded-lg w-full p-2.5 focus:ring-orange-500 focus:border-orange-500"
            >
              {sources.map((s) => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>
          </div>
          <div className="w-28">
            <label className="block text-sm text-neutral-400 mb-1.5">Count</label>
            <input
              type="number" min="1" max="200" value={count}
              onChange={(e) => setCount(parseInt(e.target.value, 10) || 1)}
              className="bg-neutral-900 border border-neutral-700 text-neutral-300 text-sm rounded-lg w-full p-2.5 focus:ring-orange-500 focus:border-orange-500"
            />
          </div>
          <div className="w-28">
            <label className="block text-sm text-neutral-400 mb-1.5">Rate (l/s)</label>
            <input
              type="number" min="0.5" max="100" step="0.5" value={rate}
              onChange={(e) => setRate(parseFloat(e.target.value) || 1)}
              className="bg-neutral-900 border border-neutral-700 text-neutral-300 text-sm rounded-lg w-full p-2.5 focus:ring-orange-500 focus:border-orange-500"
            />
          </div>
          <Button onClick={fire} disabled={busy} className="md:w-32">
            {busy ? <Radio className="w-4 h-4 mr-2 animate-pulse" /> : <Zap className="w-4 h-4 mr-2" />}
            Fire
          </Button>
          <Button variant={streaming ? 'destructive' : 'default'} onClick={toggleStream} className="md:w-40">
            {streaming ? <Square className="w-4 h-4 mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            {streaming ? 'Stop' : 'Auto-stream'}
          </Button>
          <Button variant="ghost" size="icon" onClick={clear} title="Clear feed" className="text-neutral-400 hover:text-white">
            <Trash2 className="w-4 h-4" />
          </Button>
        </CardContent>
      </Card>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <Card className="bg-neutral-900 border-neutral-700">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <div className="text-xs text-neutral-400 tracking-wider">LINES SNIFFED</div>
              <div className="text-2xl font-bold font-mono text-white">{counters.total}</div>
            </div>
            <Activity className="w-5 h-5 text-cyan-400" />
          </CardContent>
        </Card>
        <Card className="bg-neutral-900 border-neutral-700">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <div className="text-xs text-neutral-400 tracking-wider">BREACHES</div>
              <div className="text-2xl font-bold font-mono text-rose-500">{counters.security}</div>
            </div>
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          </CardContent>
        </Card>
        <Card className="bg-neutral-900 border-neutral-700">
          <CardContent className="p-4 flex items-center justify-between col-span-2 md:col-span-1">
            <div>
              <div className="text-xs text-neutral-400 tracking-wider">ERRORS</div>
              <div className="text-2xl font-bold font-mono text-amber-400">{counters.errors}</div>
            </div>
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </CardContent>
        </Card>
      </div>

      {/* Live feed */}
      <Card className="bg-black/40 border-neutral-700">
        <CardContent className="p-0">
          <div className="px-4 py-2.5 border-b border-neutral-800 flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`}></div>
            <span className="text-xs tracking-wider text-neutral-400">LIVE LOG FEED</span>
            <span className="ml-auto text-xs text-neutral-600">{events.length} buffered</span>
          </div>
          <div className="grid grid-cols-[84px_52px_84px_1fr] gap-2 px-3 py-1.5 text-[10px] text-neutral-600 uppercase border-b border-neutral-800">
            <span>Time</span><span>Level</span><span>Category</span><span>Log</span>
          </div>
          <div ref={feedRef} className="overflow-y-auto max-h-[520px]">
            {visible.length === 0 ? (
              <div className="px-4 py-16 text-center text-neutral-500 text-sm">
                No traffic yet. Pick a source and fire some lines, or start the auto-stream.
              </div>
            ) : (
              visible.map((ev) => <LiveRow key={ev.id} ev={ev} />)
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
