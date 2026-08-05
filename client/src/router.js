import { useState, useEffect } from 'react';

/**
 * Tiny path-based router (no react-router dependency).
 * Works because Vite dev + vercel.json both fall back to index.html.
 */

const NAV_EVENT = 'aizen-nav';

export function usePathname() {
  const [path, setPath] = useState(window.location.pathname);

  useEffect(() => {
    const sync = () => setPath(window.location.pathname);
    window.addEventListener('popstate', sync);
    window.addEventListener(NAV_EVENT, sync);
    return () => {
      window.removeEventListener('popstate', sync);
      window.removeEventListener(NAV_EVENT, sync);
    };
  }, []);

  return path;
}

export function navigate(path) {
  window.history.pushState({}, '', path);
  window.dispatchEvent(new Event(NAV_EVENT));
}
