import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

// The pages hosting a Google iframe (lot AN-E) need the Content-Security-Policy the console's proxy gives their own
// path (client/nginx.conf, map $obligarth_csp: Google's frames admitted there only). A single-page application keeps
// the policy of the document first loaded: reached by an in-app link from another page, such a page reloads the
// document once at its own path (no loop: the reloaded document is loaded at that path).

const FIRST_PATH = typeof window !== 'undefined' ? window.location.pathname : '';

/** true when the document was loaded at the current path; otherwise it is being reloaded there. */
export function useOwnDocument(): boolean {
  const { pathname } = useLocation();
  const own = pathname === FIRST_PATH;
  useEffect(() => {
    if (!own) window.location.replace(window.location.href);
  }, [own]);
  return own;
}
