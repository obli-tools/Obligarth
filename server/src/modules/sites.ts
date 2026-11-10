import { registerSites } from '../sites/register';

// =============================================================================
// SITES (lot P1-SITE): their hooks into the core's registries (audit actions, the filter of the device list), registered
// here and only here; index.ts calls registerSitesModule() with the other modules, before anything starts. The console
// routes are mounted by routes/index.ts, the MCP tools by modules/mcp.ts. No I/O.
// =============================================================================

let registered = false;

export function registerSitesModule(): void {
  if (registered) return;
  registered = true;
  registerSites();
}
