import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './index.css';
import { initTheme } from './utils/theme';
import { initNativeBridge } from './native/bridge';

// Apply saved theme immediately to avoid flash of wrong theme
initTheme();

// Obli Android shell glue (docs/obli-mobile.md §3): window.__obliHandleBack
// for the system back button + Escape dispatch for overlays, and system bars
// following the theme. Harmless in a normal browser.
initNativeBridge();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
