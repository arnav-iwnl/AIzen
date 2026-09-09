import React, { useEffect, useState } from 'react';
import { ChevronRight, Radio, Play, Upload, Menu } from 'lucide-react';
import { usePathname, navigate } from './router';
import { checkHealth } from './api';
import NotificationBell from './components/NotificationBell';
import { openRealtimeStream } from './api';
import { addNotification, getNotifications, unreadCount } from './notificationStore';
import RealtimeView from './views/RealtimeView';
import DemoLabView from './views/DemoLabView';
import UploadView from './views/UploadView';

const NAV_ITEMS = [
  { route: 'realtime', path: '/', icon: Radio, label: 'Realtime' },
  { route: 'upload', path: '/upload', icon: Upload, label: 'Upload' },
  { route: 'demo', path: '/demo', icon: Play, label: 'Demo' },
];

function App() {
  const path = usePathname();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [health, setHealth] = useState(null);
  const [esRef, setEsRef] = useState(null);

  // Global SSE connection — feeds NotificationBell on ALL pages
  useEffect(() => {
    const es = openRealtimeStream((payload) => {
      if (payload.type === 'attack') {
        const ev = payload.event;
        addNotification({
          type: ev.v2Attack || (ev.category === 'Security' ? 'security' : 'error'),
          confidence: ev.confidence,
          message: ev.message,
          ts: ev.ts,
          level: ev.level,
          securityTypes: ev.securityTypes,
          ip: ev.ip,
        });
      }
    }, () => setEsRef(null));
    es.onopen = () => setEsRef(es);
    return () => { if (esRef) esRef.close(); };
  }, []);

  useEffect(() => {
    checkHealth()
      .then(d => setHealth(d))
      .catch(() => setHealth({ status: 'error' }));
  }, []);

  const isActive = (item) => {
    if (item.route === 'realtime') return path === '/';
    return path === item.path;
  };

  const activeLabel = NAV_ITEMS.find((item) => isActive(item))?.label || 'Realtime';

  return (
    <div className="flex h-screen bg-[#0a0a0a] text-white font-sans antialiased">
      {/* ── Sidebar ─────────────────────────────────────────────── */}
      <div
        className={`${sidebarCollapsed ? "w-16" : "w-70"} bg-neutral-900 border-r border-neutral-700 transition-all duration-300 flex-shrink-0 fixed inset-y-0 left-0 z-50 md:relative md:inset-auto md:z-auto h-full transform ${mobileOpen ? "translate-x-0" : "-translate-x-full"} md:translate-x-0`}
      >
        <div className="flex flex-col h-full overflow-y-auto p-4">
          <div className="flex items-center justify-between mb-8">
            <div className={`${sidebarCollapsed ? "hidden" : "block"}`}>
              <h1 className="text-orange-500 font-bold text-lg tracking-wider">AIZEN</h1>
              <p className="text-neutral-500 text-xs">v1.0 LOG INTELLIGENCE</p>
            </div>
            <div className="flex items-center gap-1">
              <button
                className="md:hidden text-neutral-400 hover:text-white p-1 rounded hover:bg-neutral-800 transition-colors"
                onClick={() => setMobileOpen(false)}
                aria-label="Close menu"
              >
                ✕
              </button>
              <button
                onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                className="text-neutral-400 hover:text-orange-500 p-1 rounded hover:bg-neutral-800 transition-colors"
                aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              >
                <ChevronRight
                  className={`w-4 h-4 sm:w-5 sm:h-5 transition-transform ${sidebarCollapsed ? "" : "rotate-180"}`}
                />
              </button>
            </div>
          </div>

          <nav className="space-y-2">
            {NAV_ITEMS.map((item) => {
              const active = isActive(item);
              return (
                <button
                  key={item.route}
                  onClick={() => { navigate(item.path); setMobileOpen(false); }}
                  aria-label={item.label}
                  className={`w-full flex items-center rounded transition-colors ${
                    sidebarCollapsed ? "justify-center p-3" : "gap-3 px-3 py-2.5"
                  } ${
                    active
                      ? "bg-orange-500 text-white"
                      : "text-neutral-400 hover:text-white hover:bg-neutral-800"
                  }`}
                >
                  <item.icon className="w-5 h-5 flex-shrink-0" />
                  {!sidebarCollapsed && <span className="text-sm font-medium tracking-wider">{item.label.toUpperCase()}</span>}
                </button>
              );
            })}
          </nav>

          {!sidebarCollapsed && (
            <div className="mt-8 p-4 bg-neutral-800 border border-neutral-700 rounded">
              <div className="flex items-center gap-2 mb-2">
                <div className={`w-2 h-2 rounded-full animate-pulse ${health?.data?.status === 'healthy' ? 'bg-emerald-400' : 'bg-red-500'}`}></div>
                <span className="text-xs text-white tracking-wider">SYSTEM</span>
              </div>
              <div className="text-xs text-neutral-500">
                <div className="flex items-center gap-2">
                  <span>ENGINE:</span>
                  <span className={health?.data?.status === 'healthy' ? 'text-emerald-400' : 'text-red-500'}>{health?.data?.status === 'healthy' ? 'ONLINE' : 'OFFLINE'}</span>
                </div>
                <div>MODEL: LOCAL</div>
                <div>TOKENS: N/A</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Mobile Overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 md:hidden" onClick={() => setMobileOpen(false)} />
      )}

      {/* ── Main Content ────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Toolbar */}
        <div className="h-16 bg-neutral-800 border-b border-neutral-700 flex items-center justify-between px-4 md:px-6 flex-shrink-0">
          <div className="flex items-center gap-4">
            <button
              className="md:hidden text-neutral-300 hover:text-orange-500 transition-colors"
              onClick={() => setMobileOpen(true)}
              aria-label="Open menu"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="text-sm text-neutral-400 hidden sm:block">
              LOG INTELLIGENCE / <span className="text-orange-500">{activeLabel.toUpperCase()}</span>
            </div>
            <div className="text-sm text-neutral-300 sm:hidden">
              <span className="text-orange-500">{activeLabel.toUpperCase()}</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-xs text-neutral-500 hidden sm:block">
              {health?.data?.status === 'healthy' ? 'ALL SYSTEMS NOMINAL' : 'ENGINE OFFLINE'}
            </div>
            <NotificationBell />
          </div>
        </div>

        {/* Dashboard Content */}
        <div className="flex-1 overflow-auto">
          {path === '/upload' ? (
            <UploadView />
          ) : path === '/demo' ? (
            <DemoLabView />
          ) : (
            <RealtimeView />
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
