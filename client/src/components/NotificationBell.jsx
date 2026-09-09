import React, { useState, useEffect, useRef } from 'react';
import { Bell, ShieldAlert, X } from 'lucide-react';
import { subscribe, markAllRead, unreadCount, getNotifications, formatTime } from '../notificationStore';

const TYPE_LABELS = {
  'sql-injection': { label: 'SQL Injection', color: 'text-rose-400' },
  xss: { label: 'XSS', color: 'text-amber-400' },
  'path-traversal': { label: 'Path Traversal', color: 'text-orange-400' },
  scanner: { label: 'Scanner', color: 'text-violet-400' },
  bruteforce: { label: 'Brute Force', color: 'text-red-400' },
  'brute-force': { label: 'Brute Force', color: 'text-red-400' },
  security: { label: 'Security Event', color: 'text-rose-400' },
  error: { label: 'Error', color: 'text-red-400' },
};

export default function NotificationBell() {
  const [notifs, setNotifs] = useState(getNotifications());
  const [open, setOpen] = useState(false);
  const [unread, setUnread] = useState(unreadCount());
  const panelRef = useRef(null);

  useEffect(() => {
    return subscribe((list) => {
      setNotifs(list);
      setUnread(unreadCount());
    });
  }, []);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const toggle = () => {
    setOpen((o) => !o);
    if (!open) markAllRead();
  };

  return (
    <div className="relative" ref={panelRef}>
      <button
        onClick={toggle}
        className="relative p-2 text-neutral-400 hover:text-orange-500 transition-colors rounded hover:bg-neutral-800"
        aria-label="Notifications"
      >
        <Bell className="w-5 h-5" />
        {unread > 0 && (
          <span className="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[10px] font-bold rounded-full min-w-[18px] h-[18px] flex items-center justify-center px-1 animate-pulse">
            {unread > 99 ? '99+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-96 max-h-[480px] bg-neutral-900 border border-neutral-700 rounded-lg shadow-2xl shadow-black/50 overflow-hidden z-[100]">
          <div className="flex items-center justify-between px-4 py-3 border-b border-neutral-700">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-orange-500" />
              <span className="text-sm font-bold text-white">Notifications</span>
              {unread > 0 && (
                <span className="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded-full">{unread}</span>
              )}
            </div>
            <button onClick={() => setOpen(false)} className="text-neutral-500 hover:text-white transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="overflow-y-auto max-h-[420px]">
            {notifs.length === 0 ? (
              <div className="px-4 py-8 text-center text-neutral-500 text-sm">
                No notifications yet. Trigger demo traffic to see detections.
              </div>
            ) : (
              notifs.map((n) => {
                const meta = TYPE_LABELS[n.type] || { label: n.type, color: 'text-neutral-400' };
                return (
                  <div
                    key={n._id}
                    className={`px-4 py-3 border-b border-neutral-800 hover:bg-neutral-800/50 transition-colors ${!n._read ? 'bg-orange-500/5' : ''}`}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 bg-current ${meta.color}`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`text-xs font-bold ${meta.color}`}>{meta.label}</span>
                          <span className="text-[10px] text-neutral-500">{n.confidence}%</span>
                        </div>
                        <p className="text-xs text-neutral-400 truncate mt-0.5">{n.message?.slice(0, 100)}</p>
                        <p className="text-[10px] text-neutral-600 mt-1">{formatTime(n.ts)}</p>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
