import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

// The pages hosting a Google iframe (lot AN-E) need the Content-Security-Policy the console's proxy gives their own
// path (client/nginx.conf, map $obligarth_csp: Google's frames admitted there only). A single-page application keeps
// the policy of the document first loaded: reached by an in-app link from another page, such a page reloads the
// document once at its own path (no loop: the reloaded document is loaded at that path).
// Review AN-E: the router matches a path whatever its case and with a final slash, the proxy's map only matches the
// exact spelling; `canonical` (the page's exact path) is where the document is reloaded when the address differs
// from it (no loop either: the reloaded document is at the canonical path).

const FIRST_PATH = typeof window !== 'undefined' ? window.location.pathname : '';

/** true when the document was loaded at the page's own path; otherwise it is being reloaded there. */
export function useOwnDocument(canonical?: string): boolean {
  const { pathname } = useLocation();
  const target = canonical ?? pathname;
  const own = pathname === FIRST_PATH && pathname === target;
  useEffect(() => {
    if (own) return;
    if (target === window.location.pathname) window.location.replace(window.location.href);
    else window.location.replace(`${target}${window.location.search}${window.location.hash}`);
  }, [own, target]);
  return own;
}
