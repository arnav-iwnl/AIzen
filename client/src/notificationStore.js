/**
 * Lightweight global notification store (pub/sub).
 * RealtimeView pushes attack events; any subscriber (e.g. NotificationBell)
 * re-renders on changes. No React context needed.
 */
let notifications = [];
const listeners = new Set();
const MAX = 100;

export function addNotification(n) {
  notifications = [{ ...n, _read: false, _id: Date.now() + Math.random() }, ...notifications].slice(0, MAX);
  listeners.forEach((fn) => fn(notifications));
}

export function markAllRead() {
  notifications = notifications.map((n) => ({ ...n, _read: true }));
  listeners.forEach((fn) => fn(notifications));
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function getNotifications() { return notifications; }
export function unreadCount() { return notifications.filter((n) => !n._read).length; }

/**
 * Format timestamp as HH:MM AM/PM DD/MM/YYYY
 */
export function formatTime(iso) {
  const d = new Date(iso);
  const hh = d.getHours() % 12 || 12;
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ampm = d.getHours() >= 12 ? 'PM' : 'AM';
  const dd = String(d.getDate()).padStart(2, '0');
  const mo = String(d.getMonth() + 1).padStart(2, '0');
  const yyyy = d.getFullYear();
  return `${hh}:${mm} ${ampm} ${dd}/${mo}/${yyyy}`;
}
