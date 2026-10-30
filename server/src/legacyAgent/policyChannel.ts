// The provider of the channel 'agent' in the common artifact store (lot PONT-POL §6): each bridge-agent device (channel
// legacy_agent) with agent:* settings wants one artifact, agent:policy (identifier 'policy'), its compiled policy: the
// templates rendered with the device's values, the secrets as vault references (rendered only when the poll delivers it:
// policyDelivery.ts), the store files as blobs the agent downloads (GET /agent/v1/files/<sha>), and the items the
// compilation had to drop (`dropped`: a path two files claim, the inline budget, a rendered file too large or not JSON, a
// wipe threshold without a password, a resource of another tenant), which never make the artifact undeliverable (A1):
// the agent reports each as error/<code>. Only a body above the size limit is a problem (compile:body_too_large). The
// hash of the body never derives from a secret. No I/O in compile. A device whose desired state changes has its long
// wait woken after the commit; any other takes the change at its next poll.
import { createHash } from 'node:crypto';
import {
  AGENT_KIOSK_KEY, AGENT_WIPE_KEY, LEGACY_AGENT_POLICY_ARTIFACT_KEY, LEGACY_AGENT_POLICY_FORMAT, LEGACY_AGENT_POLICY_LIMITS as L,
  LEGACY_AGENT_SETTING_PREFIX, agentPathKey, isAgentTemplateVariable, parseAgentKey,
  type AgentPolicyDropCode, type JsonValue,
} from '@obligarth/shared';
import { canonicalJson } from '../audit/canonical';
import type { ArtifactChannelProvider, ChannelArtifact } from '../mdm/policies/artifacts';
import { variableValue, type ResolutionDevice, type ResolvedSetting } from '../mdm/policies/resolver';
import { wakeAfterCommit } from './commands';

export const AGENT_POLICY_KEY = LEGACY_AGENT_POLICY_ARTIFACT_KEY;
/** The fatal problem of a compilation (the artifact in error, never delivered). */
export const BODY_TOO_LARGE = 'compile:body_too_large';

type Obj = Record<string, JsonValue>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const sha256Hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const byKey = <T extends { key: string }>(a: T, b: T): number => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);

/** Does a value hold what only its tenant may deliver: a vault reference, a store file, a CA file (§4.5)? */
function holdsTenantResource(v: unknown, depth = 0): boolean {
  if (depth > 16 || v === null || typeof v !== 'object') return false;
  if (Array.isArray(v)) return v.some((x) => holdsTenantResource(x, depth + 1));
  const o = v as Record<string, unknown>;
  if ('$secret' in o || '$secretValue' in o || 'sha256' in o || 'caFile' in o) return true;
  return Object.values(o).some((x) => holdsTenantResource(x, depth + 1));
}

/** The vault references of a body. */
function secretRefsOf(v: unknown, out: Set<string> = new Set(), depth = 0): Set<string> {
  if (depth > 16 || v === null || typeof v !== 'object') return out;
  if (Array.isArray(v)) { v.forEach((x) => secretRefsOf(x, out, depth + 1)); return out; }
  const o = v as Record<string, unknown>;
  if (typeof o.$secret === 'string') out.add(o.$secret.toLowerCase());
  for (const x of Object.values(o)) secretRefsOf(x, out, depth + 1);
  return out;
}

/** A template rendered for a device: each {{…}} replaced by the device's value (escaped as a JSON string's content for
 *  'json'); null when a variable has no value (the resolution already reported it variable_unresolved). */
export function renderTemplate(text: string, encoding: 'text' | 'json', value: (name: string) => string | null): string | null {
  let missing = false;
  const out = text.replace(/\{\{([^{}]*)\}\}/g, (_m, raw: string) => {
    const name = raw.trim();
    const v = isAgentTemplateVariable(name) ? value(name) : null;
    if (v === null) { missing = true; return ''; }
    return encoding === 'json' ? JSON.stringify(v).slice(1, -1) : v;
  });
  return missing ? null : out;
}

/** The device name the kiosk header shows: the label (up to 500 characters) within the agent's bound (200 UTF-16 units,
 *  no control character; a longer one would make the whole kiosk unreadable on the agent), never a half surrogate. */
export function kioskDeviceName(label: string | null | undefined): string {
  let s = String(label ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 200);
  if (/[\ud800-\udbff]$/.test(s)) s = s.slice(0, -1);
  return s;
}

interface Candidate { s: ResolvedSetting; value: Obj | JsonValue }

/** The artifact agent:policy of one device from its agent:* settings (pure); null when it has none to deliver. */
export function compileAgentPolicy(device: ResolutionDevice, settings: ResolvedSetting[], tenant: { name: string; slug: string },
  tenantId: number | null): ChannelArtifact | null {
  const live = settings.filter((s) => s.kind === 'agent' && s.settingKey.startsWith(LEGACY_AGENT_SETTING_PREFIX) && !s.removed
    && s.availability.status === 'available' && s.value !== undefined);
  if (!live.length) return null;
  const dropped: Array<{ key: string; code: AgentPolicyDropCode }> = [];
  const drop = (key: string, code: AgentPolicyDropCode): void => { dropped.push({ key, code }); };
  const kept: Candidate[] = [];
  for (const s of live) {
    // A setting of another tenant's policy (the master's library) never carries this tenant's resources (B2).
    if (tenantId !== null && s.source.tenantId !== tenantId && holdsTenantResource(s.value)) { drop(s.settingKey, 'foreign_tenant_resource'); continue; }
    kept.push({ s, value: s.value as JsonValue });
  }
  const keys: Record<string, string> = {};
  const files: Obj[] = [];
  const wifi: Obj[] = [];
  const wifiRemove: Obj[] = [];
  const dpm: Obj[] = [];
  const knox: Obj[] = [];
  const certs: Obj[] = [];
  let kiosk: Obj | null = null;
  const blobs = new Set<string>();
  const inline: Array<{ entry: Obj; size: number; key: string }> = [];

  // Files: the paths taken by rank (the resolution's order: rank, priority, key); a later file on a taken path is dropped.
  const fileCands = kept.filter((c) => parseAgentKey(c.s.settingKey)?.family === 'file')
    .sort((a, b) => a.s.source.rank - b.s.source.rank || ((a.s.source as { priority?: number }).priority ?? 0) - ((b.s.source as { priority?: number }).priority ?? 0)
      || (a.s.settingKey < b.s.settingKey ? -1 : 1));
  const taken = new Set<string>();
  for (const c of fileCands) {
    const v = c.value as Obj;
    const id = parseAgentKey(c.s.settingKey)!.instance!;
    const paths = Array.isArray(v.paths) ? (v.paths as string[]) : [];
    if (paths.some((p) => taken.has(agentPathKey(p)))) { drop(c.s.settingKey, 'path_conflict'); continue; }
    const entry: Obj = {
      key: c.s.settingKey, id, paths, overwrite: (v.overwrite as string) ?? 'always', onRemove: (v.onRemove as string) ?? 'keep',
      mediaScan: v.mediaScan !== false, ...(v.allowAppDataDir === true ? { allowAppDataDir: true } : {}),
    };
    const src = v.source as Obj;
    if (src?.kind === 'store') {
      entry.blob = { sha256: src.sha256 as string, size: src.size as number };
      blobs.add(src.sha256 as string);
    } else if (src?.kind === 'template') {
      const encoding = src.encoding === 'json' ? 'json' : 'text';
      const text = renderTemplate(String(src.text ?? ''), encoding, (n) => variableValue(n as never, device, tenant, 'agent'));
      if (text === null) continue;   // unresolved: never deposited (the resolution says why)
      const bytes = Buffer.from(text, 'utf8');
      if (bytes.length > L.templateBytes) { drop(c.s.settingKey, 'template_too_large'); continue; }
      if (encoding === 'json') {
        try { JSON.parse(text); } catch { drop(c.s.settingKey, 'invalid_json'); continue; }
      }
      entry.inline = { b64: bytes.toString('base64'), sha256: sha256Hex(bytes), size: bytes.length };
      inline.push({ entry, size: bytes.length, key: c.s.settingKey });
    } else continue;
    for (const p of paths) taken.add(agentPathKey(p));
    files.push(entry);
    keys[c.s.settingKey] = c.s.valueHash;
  }
  // The inline budget of the device: the largest rendered files leave first.
  let total = inline.reduce((n, x) => n + x.size, 0);
  for (const x of [...inline].sort((a, b) => b.size - a.size || (a.key < b.key ? -1 : 1))) {
    if (total <= L.inlineTotalBytes) break;
    total -= x.size;
    files.splice(files.indexOf(x.entry), 1);
    delete keys[x.key];
    drop(x.key, 'inline_too_large');
  }

  const dpmValues = new Map<string, JsonValue>();
  for (const c of kept) {
    const k = parseAgentKey(c.s.settingKey);
    if (k?.family === 'dpm' && k.field) dpmValues.set(k.field, c.value);
  }
  for (const c of kept) {
    const k = parseAgentKey(c.s.settingKey);
    if (!k || k.family === 'file') continue;
    const v = c.value;
    switch (k.family) {
      case 'wifi': {
        const w = { ...(v as Obj) };
        const eap = isObj(w.eap) ? { ...w.eap } : null;
        if (eap && isObj(eap.caFile)) eap.caFile = { sha256: eap.caFile.sha256, size: eap.caFile.size };
        wifi.push({
          key: c.s.settingKey, ssid: w.ssid, security: w.security, hidden: w.hidden === true, priority: typeof w.priority === 'number' ? w.priority : 40,
          autoConnect: w.autoConnect !== false, preferOver: Array.isArray(w.preferOver) ? w.preferOver : [],
          ...(w.psk !== undefined ? { psk: w.psk } : {}), ...(eap ? { eap } : {}),
        });
        break;
      }
      case 'wifi.remove': wifiRemove.push({ key: c.s.settingKey, ssid: k.instance! }); break;
      case 'dpm':
        // An effective wipe threshold without an effective password quality (two policies): the threshold leaves.
        if (c.s.settingKey === AGENT_WIPE_KEY && typeof v === 'number' && v > 0) {
          const q = dpmValues.get('passwordQuality');
          if (typeof q !== 'string' || q === 'unspecified') { drop(c.s.settingKey, 'wipe_without_password'); continue; }
        }
        dpm.push({ key: c.s.settingKey, field: k.field!, value: v });
        break;
      case 'knox': knox.push({ key: c.s.settingKey, field: k.field!, value: v }); break;
      case 'cert': {
        const x = v as Obj;
        certs.push({ key: c.s.settingKey, id: k.instance!, name: x.name, pem: x.pem });
        break;
      }
      case 'kiosk': {
        const x = { ...(v as Obj) };
        const tiles = (Array.isArray(x.tiles) ? x.tiles : []).map((t) => {
          const tile = { ...(t as Obj) };
          if (isObj(tile.image)) { blobs.add(tile.image.sha256 as string); tile.image = { sha256: tile.image.sha256, size: tile.image.size }; }
          return tile;
        });
        if (isObj(x.logo)) { blobs.add(x.logo.sha256 as string); x.logo = { sha256: x.logo.sha256, size: x.logo.size }; }
        kiosk = {
          key: AGENT_KIOSK_KEY, ...x, columns: typeof x.columns === 'number' ? x.columns : 3, tiles,
          ...(x.showDeviceName === true ? { deviceName: kioskDeviceName(device.label) } : {}),
        };
        break;
      }
      default: continue;
    }
    keys[c.s.settingKey] = c.s.valueHash;
  }

  const body: Obj = {
    v: LEGACY_AGENT_POLICY_FORMAT, keys,
    files: files.sort((a, b) => (String(a.id) < String(b.id) ? -1 : 1)),
    wifi: wifi.sort(byKey as never), wifiRemove: wifiRemove.sort(byKey as never), dpm: dpm.sort(byKey as never), knox: knox.sort(byKey as never),
    certs: certs.sort(byKey as never), kiosk, blobs: [...blobs].sort(), dropped: dropped.sort(byKey) as unknown as JsonValue,
  };
  const canonical = canonicalJson(body);
  const hash = sha256Hex(canonicalJson({ channel: 'agent', identifier: 'policy', body }));
  const sources = live.map((s) => s.settingKey).sort();
  return {
    artifactKey: AGENT_POLICY_KEY, channel: 'agent', artifactType: 'agent.policy', identifier: 'policy', body, hash,
    secretRefs: [...secretRefsOf(body)].sort(), hasVariables: false, encrypt: false, sources, rendered: hash,
    problems: Buffer.byteLength(canonical, 'utf8') > L.compiledBodyBytes ? [BODY_TOO_LARGE] : [],
  };
}

/** The provider of the channel agent (registered by registerLegacyAgentModule). */
export const agentArtifactProvider: ArtifactChannelProvider = {
  name: 'agent',
  channels: ['agent'],
  claimsSetting: (key) => key.startsWith(LEGACY_AGENT_SETTING_PREFIX),
  servesDevice: (d) => d.channel === 'legacy_agent',
  compile(devices, ctx) {
    const out = new Map<number, ChannelArtifact[]>();
    for (const { device, settings } of devices) {
      const a = compileAgentPolicy(device, settings, ctx.tenant, ctx.tenantId ?? null);
      out.set(device.id, a ? [a] : []);
    }
    return out;
  },
  // Removal goes through 'removing', then 'removed' once the agent reports it holds no policy (policyReport.ts).
  async onDesiredChanged(trx, tenantId, deviceIds) {
    wakeAfterCommit(trx, tenantId, deviceIds);
  },
};
