import { registerPlatformOnlyAlertKinds } from './liveAlert.service';

// =============================================================================
// The catalogue of the alerts, opened to the modules (android-amapi §22.6, COH-22, lot AN-P; integration-apple-edge
// §12.1, I11, review INT-RC13): a module declares its kinds once, at its registration (registerAlertDefinitions),
// before anything runs; a kind that is not declared cannot be raised. The Apple integration, the bridge agent
// (legacy_agent) and Android declare theirs here.
//   - A definition that carries its texts (message, and its French) is raised by the catalogue service of the
//     integration (apple/alerts/service.ts: stable key 'apple:<kind>', i18n key, external channels): the Apple
//     kinds and the bridge agent's.
//   - A definition without a message is raised by its module (Android: android/alerts.ts, identifiers only).
// Scope 'master': a platform alert, filed in the master tenant, read by the platform administrators only (its kind is
// registered as such with the live alerts); 'both': filed in the tenant and in the master tenant.
// The texts never hold a device name, a serial number, a UDID, an account, an address nor the name of another
// tenant; the parameters are numbers, dates and configuration labels.
// =============================================================================

export type AlertScope = 'tenant' | 'master' | 'both';
export type AlertSeverity = 'info' | 'warning' | 'critical';

export interface AlertDefinition {
  /** The kind (live_alerts.kind): '<family>.<name>'. */
  key: string;
  scope: AlertScope;
  severity: AlertSeverity;
  /** English title; English message with {param} placeholders when the catalogue service renders the kind. */
  title: string;
  message?: string;
  /** The French texts of a rendered kind (the external channels, in the tenant's language). */
  fr?: { title: string; message: string };
  /** The console's i18n key of the texts. */
  i18nKey: string;
}

export interface RegisteredAlertDefinition extends AlertDefinition {
  /** The module that declared it. */
  module: string;
}

/**
 * The kinds the catalogue service raises, by module augmentation (type only): a module adds its kinds with
 * `declare module '…/services/alertCatalog' { interface CatalogAlertKinds extends Record<MyKind, true> {} }`.
 */
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface CatalogAlertKinds {}
export type CatalogAlertKind = keyof CatalogAlertKinds & string;

const KIND_RE = /^[a-z][a-z_]*\.[a-z0-9_]+$/;
const byModule = new Map<string, Map<string, RegisteredAlertDefinition>>();
/** The rendered kinds (with a message), one module each: the catalogue service's. */
const rendered = new Map<string, RegisteredAlertDefinition>();

/**
 * Declares the alerts of a module. A rendered kind (with a message) is rendered by one module; the same kind may be
 * declared by another module with the same scope (Android reuses enrollment.* of the tenant alerts). Throws on an invalid
 * or duplicate definition: a defect of the code, at start.
 */
export function registerAlertDefinitions(module: string, defs: readonly AlertDefinition[]): void {
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(module)) throw new Error('alert definitions: invalid module');
  const mine = byModule.get(module) ?? new Map<string, RegisteredAlertDefinition>();
  const platformOnly: string[] = [];
  for (const d of defs) {
    const fail = (m: string): never => { throw new Error(`alert ${JSON.stringify(d?.key)} of ${module}: ${m}`); };
    if (!KIND_RE.test(String(d.key))) fail('invalid kind');
    if (!['tenant', 'master', 'both'].includes(d.scope)) fail('invalid scope');
    if (!['info', 'warning', 'critical'].includes(d.severity)) fail('invalid severity');
    if (!d.title || d.title.length > 120 || d.title.includes('{')) fail('invalid title');
    if (!d.i18nKey || !/^[a-z][A-Za-z0-9_.]{0,127}$/.test(d.i18nKey)) fail('invalid i18n key');
    if (mine.has(d.key)) fail('declared twice');
    if (d.message !== undefined && rendered.has(d.key)) fail(`rendered by ${rendered.get(d.key)!.module} already`);
    for (const [other, m] of byModule) {
      const x = m.get(d.key);
      if (x && x.scope !== d.scope) fail(`declared by ${other} with another scope`);
    }
    const def: RegisteredAlertDefinition = { ...d, module };
    mine.set(d.key, def);
    if (d.message !== undefined) rendered.set(d.key, def);
    if (d.scope === 'master') platformOnly.push(d.key);
  }
  byModule.set(module, mine);
  // The platform alerts are read by the platform administrators only.
  if (platformOnly.length) registerPlatformOnlyAlertKinds(platformOnly);
}

/** The rendered kind (raised by the catalogue service), or null. */
export function catalogAlert(kind: string): RegisteredAlertDefinition | null {
  return rendered.get(kind) ?? null;
}

/** Is `kind` a rendered kind of the catalogue (own keys only)? */
export function isCatalogAlertKind(kind: string): kind is CatalogAlertKind {
  return rendered.has(kind);
}

/** The definition of a kind declared by `module`, or null. */
export function alertDefinitionOf(module: string, kind: string): RegisteredAlertDefinition | null {
  return byModule.get(module)?.get(kind) ?? null;
}

/** Every definition, by module then kind (the console, the tests). */
export function alertDefinitions(): RegisteredAlertDefinition[] {
  return [...byModule.values()].flatMap((m) => [...m.values()]);
}
