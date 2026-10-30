import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Bot, RefreshCw, ShieldOff } from 'lucide-react';
import { type McpBlockView, type McpSettingsView, type McpTenantIpPolicy } from '@obligarth/shared';
import { accessKeysApi } from '@/api/accessKeys.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { IconButton } from '@/components/common/IconButton';
import { Input } from '@/components/common/Input';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { RelativeDate } from '@/components/accessKeys/KeyList';
import { useTenantStore } from '@/store/tenantStore';
import { apiErrorMessage, trCode } from '@/utils/apiError';
import type { Tone } from '@/components/accessKeys/accessKeyLabels';

// Settings › MCP server (docs: specs mcp-server §3.6, §6.1, owner decision 3), platform administrators on the master
// tenant: the IP policy of /mcp (forced allow-list, per-tenant overrides, thresholds of the rate mode), the caps of
// the authorizations, Obliguard, and the local blocks. A change, a manual unblock: a fresh second factor (asked by
// the client's interceptor). The mode (strict / rate / closed) is computed by the server from the active keys.

type Draft = Omit<McpSettingsView, 'mode' | 'activeKeys' | 'openKeys'>;
type NumberKey = { [K in keyof Draft]: Draft[K] extends number ? K : never }[keyof Draft];

const NUMBER_FIELDS: Array<{ key: NumberKey; min: number; max: number; fallback: string }> = [
  { key: 'minPrefixV4', min: 8, max: 32, fallback: 'Narrowest IPv4 network of a key (prefix)' },
  { key: 'minPrefixV6', min: 32, max: 128, fallback: 'Narrowest IPv6 network of a key (prefix)' },
  { key: 'failureThreshold', min: 3, max: 100, fallback: 'Failed attempts before a block (rate mode)' },
  { key: 'failureWindowSeconds', min: 60, max: 86_400, fallback: 'Window of the failed attempts (seconds)' },
  { key: 'blockSeconds', min: 300, max: 31_536_000, fallback: 'Duration of a block (seconds)' },
  { key: 'knownIpDays', min: 0, max: 365, fallback: 'Days an address of a revoked or expired key stays known' },
  { key: 'maxNewBlocksPerMinute', min: 5, max: 1000, fallback: 'New blocks per minute at most' },
  { key: 'prefixBlockThreshold', min: 2, max: 64, fallback: 'Blocked addresses of one IPv6 /64 before the /64 is blocked' },
  { key: 'keyRequestsPerMinute', min: 10, max: 6000, fallback: 'Requests per minute of one key' },
  { key: 'authorizationMinutes', min: 2, max: 60, fallback: 'Validity of an authorization (minutes)' },
  { key: 'maxPendingPerKey', min: 1, max: 50, fallback: 'Waiting authorizations per key' },
  { key: 'maxPendingPerUser', min: 1, max: 200, fallback: 'Waiting authorizations per user' },
  { key: 'maxCreatedPerKeyHour', min: 1, max: 500, fallback: 'Authorizations created per key per hour' },
];

const MODE_TONE: Record<McpSettingsView['mode'], Tone> = { strict: 'green', rate: 'amber', closed: 'gray' };
const OBLIGUARD_TONE: Record<McpBlockView['obliguardStatus'], Tone> = {
  pending: 'blue', sent: 'green', failed: 'red', disabled: 'gray', withdrawn: 'gray', skipped: 'violet',
};

function draftOf(s: McpSettingsView): Draft {
  const { mode: _m, activeKeys: _a, openKeys: _o, ...rest } = s;
  return rest;
}

export function McpSettingsSection() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const tenants = useTenantStore((s) => s.tenants);
  const [cfg, setCfg] = useState<McpSettingsView | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [neverText, setNeverText] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [policies, setPolicies] = useState<Record<number, McpTenantIpPolicy>>({});
  const [blocks, setBlocks] = useState<McpBlockView[] | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await accessKeysApi.admin.settings();
      setCfg(s);
      setDraft(draftOf(s));
      setNeverText(s.neverBlock.join(', '));
    } catch {
      setCfg(null);
    }
  }, []);
  const loadBlocks = useCallback(() => {
    accessKeysApi.admin.blocks(true).then(setBlocks).catch(() => setBlocks([]));
  }, []);
  const readable = cfg !== null;
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (readable) loadBlocks(); }, [readable, loadBlocks]);
  useEffect(() => {
    // The per-tenant overrides, one reading a tenant (only once the settings could be read: master tenant).
    if (!readable) return undefined;
    let stop = false;
    Promise.all(tenants.map(async (x) => [x.id, await accessKeysApi.admin.tenantPolicy(x.id).catch(() => 'inherit' as const)] as const))
      .then((rows) => { if (!stop) setPolicies(Object.fromEntries(rows)); });
    return () => { stop = true; };
  }, [tenants, readable]);

  if (!cfg || !draft) return null;

  const neverBlock = neverText.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const numbersValid = NUMBER_FIELDS.every((f) => Number.isInteger(draft[f.key]) && draft[f.key] >= f.min && draft[f.key] <= f.max);
  const urlValid = draft.obliguardUrl === null || /^https{0,1}:\/\/[^@ ]+$/.test(draft.obliguardUrl);
  const dirty = JSON.stringify({ ...draft, neverBlock }) !== JSON.stringify(draftOf(cfg));

  const save = async () => {
    setSaving(true);
    try {
      const r = await accessKeysApi.admin.saveSettings({ ...draft, neverBlock });
      if (r) { setCfg(r); setDraft(draftOf(r)); setNeverText(r.neverBlock.join(', ')); toast.success(t('common.saved') || 'Saved'); }
      else toast.success(t('settings.mcp.pendingApproval') || 'The change waits for its approval.');
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const setPolicy = async (tenantId: number, v: McpTenantIpPolicy) => {
    try {
      const done = await accessKeysApi.admin.setTenantPolicy(tenantId, v);
      if (done) { setPolicies((p) => ({ ...p, [tenantId]: v })); toast.success(t('common.saved') || 'Saved'); void load(); }
      else toast.success(t('settings.mcp.pendingApproval') || 'The change waits for its approval.');
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err));
    }
  };

  const test = async () => {
    setTesting(true);
    try {
      const r = await accessKeysApi.admin.obliguardTest();
      if (r.ok) toast.success(t('settings.mcp.obliguardOk') || 'Obliguard answered.');
      else toast.error(r.error || (t('settings.mcp.obliguardFailed') || 'Obliguard could not be reached.'));
    } catch (err) {
      toast.error(apiErrorMessage(err));
    } finally {
      setTesting(false);
    }
  };

  const unblock = async (b: McpBlockView) => {
    const ok = await confirm({
      message: t('settings.mcp.unblockConfirm', { ip: b.ip }) || `Unblock ${b.ip}? Obliguard is told to lift its ban too.`,
      confirmLabel: t('settings.mcp.unblock') || 'Unblock',
    });
    if (!ok) return;
    try {
      await accessKeysApi.admin.unblock(b.id);
      toast.success(t('settings.mcp.unblocked') || 'Address unblocked.');
      loadBlocks();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err));
    }
  };

  const modeLabel = trCode(`settings.mcp.mode.${cfg.mode}`, cfg.mode);
  const rowCls = 'flex flex-wrap items-start justify-between gap-4 p-4';

  return (
    <div>
      <h2 className="mb-2 flex items-center gap-2 text-lg font-semibold text-text-primary">
        <Bot size={18} className="text-accent" />
        {t('settings.mcp.title') || 'MCP server (AI agents)'}
      </h2>
      <p className="mb-4 text-sm text-text-muted">
        {t('settings.mcp.intro') || 'Who may reach /mcp. When every active key lists its addresses, the server is in strict mode: any other address is blocked at once, for good, and reported to Obliguard. As soon as one key accepts any address, it falls back to the rate mode: failed attempts are counted per address, then blocked.'}
      </p>
      <div className="overflow-hidden rounded-xl bg-bg-secondary">
        <div className={rowCls}>
          <div className="min-w-0">
            <p className="text-sm font-medium text-text-primary">{t('settings.mcp.currentMode') || 'Current mode'}</p>
            <p className="mt-0.5 text-xs text-text-muted">
              {t('settings.mcp.keysCount', { active: cfg.activeKeys, open: cfg.openKeys }) || `${cfg.activeKeys} active key(s), ${cfg.openKeys} without an address list`}
            </p>
          </div>
          <StateBadge tone={MODE_TONE[cfg.mode]} label={modeLabel} size="md" />
        </div>
        <div className={rowCls}>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-text-primary">{t('settings.mcp.forceIp') || 'Require an address list on every key'}</p>
            <p className="mt-0.5 text-xs text-text-muted">
              {t('settings.mcp.forceIpDesc') || 'A key without addresses then refuses the tenants concerned; a tenant can be exempted or forced below.'}
            </p>
          </div>
          <ToggleSwitch checked={draft.forceIpAllowList} onChange={(v) => setDraft({ ...draft, forceIpAllowList: v })}
            ariaLabel={t('settings.mcp.forceIp') || 'Require an address list on every key'} />
        </div>
        <div className="grid gap-3 p-4 sm:grid-cols-2">
          {NUMBER_FIELDS.map((f) => (
            <Input
              key={f.key}
              type="number"
              inputMode="numeric"
              min={f.min}
              max={f.max}
              label={trCode(`settings.mcp.fields.${f.key}`, f.fallback)}
              value={Number.isFinite(draft[f.key]) ? draft[f.key] : ''}
              onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value === '' ? NaN : Number(e.target.value) })}
              error={Number.isInteger(draft[f.key]) && draft[f.key] >= f.min && draft[f.key] <= f.max ? undefined : `${f.min} – ${f.max}`}
            />
          ))}
        </div>
        <div className="space-y-3 p-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-text-primary">{t('settings.mcp.obliguard') || 'Report blocks to Obliguard'}</p>
              <p className="mt-0.5 text-xs text-text-muted">
                {t('settings.mcp.obliguardDesc') || 'Public addresses only. Without an address, Obliguard is found through Obligate.'}
              </p>
            </div>
            <ToggleSwitch checked={draft.obliguardEnabled} onChange={(v) => setDraft({ ...draft, obliguardEnabled: v })}
              ariaLabel={t('settings.mcp.obliguard') || 'Report blocks to Obliguard'} />
          </div>
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <Input
                label={t('settings.mcp.obliguardUrl') || 'Obliguard address (optional)'}
                value={draft.obliguardUrl ?? ''}
                placeholder="https://guard.example.com"
                onChange={(e) => setDraft({ ...draft, obliguardUrl: e.target.value.trim() === '' ? null : e.target.value.trim() })}
                error={urlValid ? undefined : (t('settings.mcp.urlInvalid') || 'An http(s) address without credentials.')}
              />
            </div>
            <Button variant="secondary" size="sm" onClick={test} loading={testing} className="mb-0.5">{t('settings.mcp.test') || 'Test'}</Button>
          </div>
          <Input
            label={t('settings.mcp.neverBlock') || 'Never blocked (addresses or networks, comma separated)'}
            value={neverText}
            placeholder="198.51.100.0/24, 2001:db8::/48"
            onChange={(e) => setNeverText(e.target.value)}
          />
        </div>
        <div className="flex items-center justify-end p-4">
          <Button size="sm" onClick={save} loading={saving} disabled={!dirty || !numbersValid || !urlValid}>
            {t('common.save') || 'Save'}
          </Button>
        </div>
      </div>

      {tenants.length > 0 && (
        <div className="mt-4 overflow-hidden rounded-xl bg-bg-secondary">
          <div className="bg-bg-tertiary/50 px-4 py-2 text-[10px] uppercase tracking-wider text-text-muted">
            {t('settings.mcp.tenantPolicies') || 'Address list per tenant'}
          </div>
          <ul>
            {tenants.map((x) => (
              <li key={x.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 text-sm hover:bg-bg-tertiary">
                <span className="min-w-0 truncate text-text-primary">{x.name}</span>
                <SegmentedTabs<McpTenantIpPolicy>
                  size="sm"
                  fill={false}
                  value={policies[x.id] ?? 'inherit'}
                  onChange={(v) => setPolicy(x.id, v)}
                  tabs={[
                    { id: 'inherit', label: t('settings.mcp.policy.inherit') || 'Instance setting' },
                    { id: 'force', label: t('settings.mcp.policy.force') || 'Required' },
                    { id: 'exempt', label: t('settings.mcp.policy.exempt') || 'Exempt' },
                  ]}
                />
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-4 overflow-hidden rounded-xl bg-bg-secondary">
        <div className="flex items-center bg-bg-tertiary/50 px-4 py-2 text-[10px] uppercase tracking-wider text-text-muted">
          <span className="flex-1">{t('settings.mcp.blocks') || 'Blocked addresses'}</span>
          <IconButton size="sm" label={t('common.refresh') || 'Refresh'} icon={<RefreshCw size={12} />} onClick={loadBlocks} />
        </div>
        {blocks === null ? <p className="px-4 py-3 text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
          : blocks.length === 0 ? <p className="px-4 py-3 text-sm text-text-muted">{t('settings.mcp.noBlocks') || 'No address is blocked.'}</p> : (
            <ul>
              {blocks.map((b) => (
                <li key={b.id} className="flex flex-wrap items-center gap-3 px-4 py-2 text-sm hover:bg-bg-tertiary">
                  <span className="min-w-0 flex-1">
                    <span className="block font-mono text-text-primary">{b.ip}</span>
                    <span className="block text-[11px] text-text-muted">
                      {trCode(`settings.mcp.source.${b.source}`, b.source)} · {t('settings.mcp.hits', { count: b.hitCount }) || `${b.hitCount} attempt(s)`} · {b.blockedUntil
                        ? <>{t('settings.mcp.until') || 'until'} <RelativeDate iso={b.blockedUntil} /></>
                        : (t('settings.mcp.permanent') || 'permanent')}
                    </span>
                  </span>
                  <StateBadge tone={OBLIGUARD_TONE[b.obliguardStatus]} label={trCode(`settings.mcp.obliguardStatus.${b.obliguardStatus}`, b.obliguardStatus)}
                    title={b.obliguardError ?? undefined} />
                  <IconButton label={t('settings.mcp.unblock') || 'Unblock'} icon={<ShieldOff className="h-4 w-4" />} variant="accent" onClick={() => unblock(b)} />
                </li>
              ))}
            </ul>
          )}
      </div>
    </div>
  );
}
