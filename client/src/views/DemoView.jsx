import React, { useState, useEffect } from 'react';
import {
  Play, Square, Radio, Zap, Database, Code2, FolderSearch, KeyRound, Bug,
  Download, Upload, FolderLock, ServerCrash, Rocket, Shuffle, ExternalLink,
} from 'lucide-react';
import { Badge, Button, Card, CardContent } from '../components/ui';
import { getDemoActions, triggerDemo } from '../api';
import { navigate } from '../router';

const ACTION_ICONS = {
  sqli: Database, xss: Code2, 'path-traversal': FolderSearch, 'admin-bruteforce': KeyRound,
  scanner: Bug, 'get-flood': Download, 'post-flood': Upload, 'directory-forbidden': FolderLock,
  'backend-error': ServerCrash, 'apache-startup': Rocket, mixed: Shuffle,
};

const CATEGORY_COLORS = {
  Security: 'text-rose-400 border-rose-900/50 bg-rose-950/20',
  Traffic: 'text-cyan-400 border-cyan-900/50 bg-cyan-950/20',
  Operational: 'text-amber-400 border-amber-900/50 bg-amber-950/20',
};

export default function DemoView({ stream, setStream, toggleStream }) {
  const [actions, setActions] = useState([]);
  const [counts, setCounts] = useState({});
  const [busy, setBusy] = useState(null);
  const [lastFire, setLastFire] = useState(null);

  useEffect(() => {
    getDemoActions().then((r) => {
      if (r.data) {
        setActions(r.data);
        const initial = {};
        r.data.forEach((a) => (initial[a.id] = 10));
        setCounts(initial);
      }
    });
  }, []);

  const fire = async (id) => {
    setBusy(id);
    try {
      const res = await triggerDemo(id, counts[id] || 1);
      setLastFire({ action: id, generated: res.data?.generated });
      setTimeout(() => setLastFire(null), 2500);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="p-6 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-orange-500/20 rounded-full flex items-center justify-center">
            <Zap className="w-5 h-5 text-orange-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Demo Traffic</h1>
            <p className="text-sm text-neutral-400">Trigger realistic traffic — payloads are seeded from the data/ corpus</p>
          </div>
        </div>
        <Button variant="outline" size="sm" className="border-neutral-700 text-neutral-300 hover:bg-neutral-800" onClick={() => navigate('/')}>
          <ExternalLink className="w-4 h-4 mr-2" /> View live in Realtime
        </Button>
      </div>

      {/* Auto-stream control */}
      <Card className="bg-neutral-900 border-neutral-700">
        <CardContent className="p-5 flex flex-col md:flex-row md:items-end gap-4">
          <div className="flex-1 min-w-40">
            <label className="block text-sm text-neutral-400 mb-1.5">Auto-stream action</label>
            <select
              value={stream.action}
              onChange={(e) => setStream((s) => ({ ...s, action: e.target.value }))}
              disabled={stream.running}
              className="bg-neutral-900 border border-neutral-700 text-neutral-300 text-sm rounded-lg w-full p-2.5 focus:ring-orange-500 focus:border-orange-500"
            >
              {actions.map((a) => (
                <option key={a.id} value={a.id}>{a.label}</option>
              ))}
            </select>
          </div>
          <div className="w-32">
            <label className="block text-sm text-neutral-400 mb-1.5">Rate (lines/sec)</label>
            <input
              type="number"
              min="0.5"
              max="100"
              step="0.5"
              value={stream.rate}
              onChange={(e) => setStream((s) => ({ ...s, rate: parseFloat(e.target.value) || 1 }))}
              disabled={stream.running}
              className="bg-neutral-900 border border-neutral-700 text-neutral-300 text-sm rounded-lg w-full p-2.5 focus:ring-orange-500 focus:border-orange-500"
            />
          </div>
          <Button variant={stream.running ? 'destructive' : 'default'} onClick={toggleStream} className="md:w-40">
            {stream.running ? <Square className="w-4 h-4 mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            {stream.running ? 'Stop Stream' : 'Start Stream'}
          </Button>
          <div className="flex items-center gap-2 text-sm text-neutral-500 min-w-40">
            <Radio className={`w-4 h-4 ${stream.running ? 'text-emerald-400 animate-pulse' : ''}`} />
            {stream.running ? `Streaming ${stream.action} @ ${stream.rate}/s` : 'Stream idle'}
          </div>
        </CardContent>
      </Card>

      {lastFire && (
        <div className="text-sm text-emerald-400 bg-emerald-950/30 border border-emerald-900/40 rounded-lg px-4 py-2.5">
          Fired {lastFire.generated} {lastFire.action} log lines → watch them in Real-time
        </div>
      )}

      {/* Action grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {actions.map((a) => {
          const Icon = ACTION_ICONS[a.id] || Zap;
          const color = CATEGORY_COLORS[a.category] || 'text-gray-400 border-gray-800 bg-gray-900/20';
          return (
            <Card key={a.id} className="bg-neutral-900 border-neutral-700 hover:border-orange-500/50 transition-colors">
              <CardContent className="p-5 flex flex-col gap-3 h-full">
                <div className="flex items-start gap-3">
                  <div className={`w-10 h-10 rounded-lg border flex items-center justify-center flex-shrink-0 ${color}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="font-bold text-white text-sm">{a.label}</h3>
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-neutral-400">{a.category}</Badge>
                    </div>
                    <p className="text-xs text-neutral-400 mt-1">{a.description}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 mt-auto pt-2">
                  <input
                    type="number"
                    min="1"
                    max="200"
                    value={counts[a.id] || 1}
                    onChange={(e) => setCounts((c) => ({ ...c, [a.id]: Math.max(1, parseInt(e.target.value) || 1) }))}
                    className="bg-neutral-900 border border-neutral-700 text-neutral-300 text-sm rounded-lg w-20 p-2 focus:ring-orange-500 focus:border-orange-500"
                    aria-label={`${a.label} count`}
                  />
                  <Button
                    size="sm"
                    className="flex-1"
                    disabled={busy === a.id}
                    onClick={() => fire(a.id)}
                  >
                    {busy === a.id ? <Radio className="w-4 h-4 mr-2 animate-pulse" /> : <Zap className="w-4 h-4 mr-2" />}
                    Fire
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
