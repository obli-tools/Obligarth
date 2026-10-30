import {
  AGENT_KIOSK_KEY, agentCertKey, agentDpmKey, agentFileKey, agentKnoxKey, agentWifiKey, agentWifiRemoveKey, isAgentTemplateVariable,
  variablesInString,
  type AgentTemplateVariable, type JsonValue, type LegacyAgentPolicySection,
} from '@obligarth/shared';
import { valueHashOf } from '../policies/contributions';

// =============================================================================
// What the section legacyAgent of a policy version brings to the resolution
// (lot PONT-POL §5.3): one setting key per inheritable unit — a file by its id
// (agent:file[<id>]), a network by its SSID (agent:wifi[<ssid>]), a network to
// remove (agent:wifi.remove[<ssid>]), the kiosk as a whole (agent:kiosk), a
// device-administrator or Knox field (agent:dpm.<f>, agent:knox.<f>), a CA
// (agent:cert[<id>]). The value is kept as the version stores it: secrets as
// references, templates as templates; its hash never derives from a secret.
// The variables come only from the text of a file template (A5). Only a
// validated section is read.
// =============================================================================

export interface LegacyAgentContribution {
  settingKey: string;
  value: JsonValue;
  valueHash: string;
  variables: AgentTemplateVariable[];
}

/** The contributions of a section, sorted by setting key. */
export function legacyAgentContributions(section: LegacyAgentPolicySection | undefined | null): LegacyAgentContribution[] {
  const out: LegacyAgentContribution[] = [];
  const seen = new Set<string>();
  if (!section || typeof section !== 'object' || Array.isArray(section)) return out;
  const push = (settingKey: string, value: JsonValue, variables: AgentTemplateVariable[] = []): void => {
    if (seen.has(settingKey)) return;
    seen.add(settingKey);
    out.push({ settingKey, value, valueHash: valueHashOf(value), variables });
  };
  for (const f of section.files ?? []) {
    if (!f || typeof f.id !== 'string') continue;
    const { id: _id, ...value } = f;
    const vars = f.source?.kind === 'template' && typeof f.source.text === 'string'
      ? variablesInString(f.source.text, isAgentTemplateVariable).known : [];
    push(agentFileKey(f.id), value as unknown as JsonValue, vars);
  }
  for (const w of section.wifi ?? []) if (w && typeof w.ssid === 'string') push(agentWifiKey(w.ssid), w as unknown as JsonValue);
  for (const s of section.wifiRemove ?? []) if (typeof s === 'string') push(agentWifiRemoveKey(s), true);
  if (section.kiosk) push(AGENT_KIOSK_KEY, section.kiosk as unknown as JsonValue);
  for (const [field, v] of Object.entries(section.dpm ?? {})) push(agentDpmKey(field), v);
  for (const [field, v] of Object.entries(section.knox ?? {})) push(agentKnoxKey(field), v);
  for (const c of section.certs ?? []) {
    if (!c || typeof c.id !== 'string') continue;
    const { id: _id, ...value } = c;
    push(agentCertKey(c.id), value as unknown as JsonValue);
  }
  return out.sort((x, y) => (x.settingKey < y.settingKey ? -1 : x.settingKey > y.settingKey ? 1 : 0));
}
