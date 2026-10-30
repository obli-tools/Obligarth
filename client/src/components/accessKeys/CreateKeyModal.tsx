import { useEffect, useMemo, useState, type KeyboardEvent } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, Copy, FolderTree, KeyRound, Search, X } from 'lucide-react';
import {
  MCP_KEY_BOUNDS, MCP_SCOPE_KEYS, MCP_SCOPES, type AccessKeyCreateBody, type AccessKeyCreated, type AccessKeyOptions,
  type DeviceGroupTreeNode, type DeviceSummary, type McpScope,
} from '@obligarth/shared';
import { accessKeysApi } from '@/api/accessKeys.api';
import { isStepUpHandled } from '@/api/client';
import { groupsApi } from '@/api/groups.api';
import { listManagedDevices } from '@/api/mdm.api';
import { Button } from '@/components/common/Button';
import { IconButton } from '@/components/common/IconButton';
import { Input } from '@/components/common/Input';
import { Modal } from '@/components/common/Modal';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { StyledCheckbox } from '@/components/devices/StyledCheckbox';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage } from '@/utils/apiError';
import { copyText } from '@/utils/clipboard';
import { cn } from '@/utils/cn';
import { deviceMatchesSearch } from '@/utils/deviceSearch';
import { scopeLabel } from './accessKeyLabels';

// The creation of a personal access key (docs: specs mcp-server §6.5): a name, an expiry, the tenants, groups and
// devices it may reach, the scopes (only those the user holds in a chosen tenant), an optional IP allow-list. The
// server re-checks everything and asks a fresh second factor; the token comes back ONCE, with the command that
// connects Claude Code to it. Groups and devices are picked among those the console lists in this session (the
// current tenant, or every tenant for a platform administrator on the master tenant).

type TenantChoice = 'current' | 'list' | 'all';
type Mode = 'all' | 'list';
const EXPIRIES = ['30', '90', '180', '365'] as const;
type Expiry = typeof EXPIRIES[number];

/** A group of the tree, flattened with its depth and its ancestors (a group includes its descendants). */
interface FlatGroup { node: DeviceGroupTreeNode; depth: number; ancestors: number[] }

function flatten(nodes: DeviceGroupTreeNode[], depth = 0, ancestors: number[] = [], out: FlatGroup[] = []): FlatGroup[] {
  for (const n of nodes) {
    out.push({ node: n, depth, ancestors });
    if (n.children?.length) flatten(n.children, depth + 1, [...ancestors, n.id], out);
  }
  return out;
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_RE = /^[0-9a-f:.]+$/i;

/** An address or a network of the allow-list, checked as the server will (minimum prefixes): null when valid. */
export function ipEntryError(entry: string, minV4: number, minV6: number): 'invalid' | 'tooWide' | null {
  const [addr, prefixText, extra] = entry.trim().split('/');
  if (!addr || extra !== undefined) return 'invalid';
  if (prefixText !== undefined && !/^\d{1,3}$/.test(prefixText)) return 'invalid';
  const m = IPV4_RE.exec(addr);
  if (m) {
    if (m.slice(1).some((x) => Number(x) > 255)) return 'invalid';
    const p = prefixText === undefined ? 32 : Number(prefixText);
    if (p > 32) return 'invalid';
    return p < minV4 ? 'tooWide' : null;
  }
  if (addr.includes(':') && IPV6_RE.test(addr) && (addr.match(/::/g) ?? []).length <= 1) {
    const p = prefixText === undefined ? 128 : Number(prefixText);
    if (p > 128) return 'invalid';
    return p < minV6 ? 'tooWide' : null;
  }
  return 'invalid';
}

interface Props {
  open: boolean;
  onClose: () => void;
  /** A key was created (the list reloads). */
  onCreated: () => void;
}

export function CreateKeyModal({ open, onClose, onCreated }: Props) {
  const { t } = useTranslation();
  const isPlatformAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const currentTenantId = useTenantStore((s) => s.currentTenantId);

  const [options, setOptions] = useState<AccessKeyOptions | null>(null);
  const [optionsError, setOptionsError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [expiry, setExpiry] = useState<Expiry>('90');
  const [tenantChoice, setTenantChoice] = useState<TenantChoice>('current');
  const [chosenTenants, setChosenTenants] = useState<Set<number>>(new Set());
  const [groupMode, setGroupMode] = useState<Mode>('all');
  const [chosenGroups, setChosenGroups] = useState<Set<string>>(new Set());
  const [deviceMode, setDeviceMode] = useState<Mode>('all');
  const [chosenDevices, setChosenDevices] = useState<Set<string>>(new Set());
  const [scopes, setScopes] = useState<Set<McpScope>>(new Set(['devices.read']));
  const [ipAllow, setIpAllow] = useState<string[]>([]);
  const [ipDraft, setIpDraft] = useState('');
  const [groupTree, setGroupTree] = useState<DeviceGroupTreeNode[] | null>(null);
  const [devices, setDevices] = useState<DeviceSummary[] | null>(null);
  const [deviceQuery, setDeviceQuery] = useState('');
  const [saving, setSaving] = useState(false);
  const [created, setCreated] = useState<AccessKeyCreated | null>(null);

  // A fresh form at each opening.
  useEffect(() => {
    if (!open) return;
    setOptions(null); setOptionsError(null); setName(''); setExpiry('90'); setTenantChoice('current'); setChosenTenants(new Set());
    setGroupMode('all'); setChosenGroups(new Set()); setDeviceMode('all'); setChosenDevices(new Set());
    setScopes(new Set(['devices.read'])); setIpAllow([]); setIpDraft(''); setDeviceQuery(''); setCreated(null);
    accessKeysApi.options().then(setOptions).catch((err) => setOptionsError(apiErrorMessage(err)));
  }, [open]);

  // The pickers load what the console lists in this session, once, when first needed.
  useEffect(() => {
    if (open && groupMode === 'list' && groupTree === null) groupsApi.tree().then(setGroupTree).catch(() => setGroupTree([]));
  }, [open, groupMode, groupTree]);
  useEffect(() => {
    if (open && deviceMode === 'list' && devices === null) listManagedDevices(5000).then(setDevices).catch(() => setDevices([]));
  }, [open, deviceMode, devices]);

  const tenantsById = useMemo(() => new Map((options?.tenants ?? []).map((x) => [x.tenantId, x])), [options]);
  const currentAllowed = currentTenantId !== null && tenantsById.has(currentTenantId);
  // The current tenant cannot be given (the capability is not held there): the user chooses among his tenants.
  useEffect(() => { if (options && !currentAllowed) setTenantChoice((c) => (c === 'current' ? 'list' : c)); }, [options, currentAllowed]);

  /** The tenants of the perimeter as chosen (for 'all': the user's tenants today, for the offered scopes). */
  const perimeterTenants = useMemo<number[]>(() => {
    if (!options) return [];
    if (tenantChoice === 'all') return options.tenants.map((x) => x.tenantId);
    if (tenantChoice === 'current') return currentAllowed ? [currentTenantId!] : [];
    return [...chosenTenants].filter((id) => tenantsById.has(id));
  }, [options, tenantChoice, chosenTenants, currentAllowed, currentTenantId, tenantsById]);
  const perimeterSet = useMemo(() => new Set(perimeterTenants), [perimeterTenants]);

  // A scope is offered when the user holds it in at least one tenant of the perimeter (the server re-checks).
  const offered = useMemo(() => {
    const s = new Set<McpScope>();
    for (const id of perimeterTenants) for (const sc of tenantsById.get(id)?.scopes ?? []) s.add(sc);
    return s;
  }, [perimeterTenants, tenantsById]);
  const ipForced = perimeterTenants.some((id) => tenantsById.get(id)?.forceIpAllowList);

  const groupsInPerimeter = useMemo(() => {
    if (!groupTree) return [];
    return flatten(groupTree).filter((g) => perimeterSet.has(g.node.tenantId));
  }, [groupTree, perimeterSet]);
  const devicesInPerimeter = useMemo(
    () => (devices ?? []).filter((d) => perimeterSet.has(d.tenantId) && deviceMatchesSearch(d, deviceQuery)),
    [devices, perimeterSet, deviceQuery],
  );
  const multiTenantPick = perimeterTenants.length > 1;

  const gKey = (tenantId: number, id: number) => `${tenantId}:${id}`;
  const toggleIn = <T,>(set: Set<T>, v: T): Set<T> => { const n = new Set(set); if (n.has(v)) n.delete(v); else n.add(v); return n; };

  // What is chosen and still in the perimeter (a tenant unchecked drops its groups and devices).
  const groupItems = [...chosenGroups].map((k) => k.split(':').map(Number)).filter(([tid]) => perimeterSet.has(tid))
    .map(([tenantId, groupId]) => ({ tenantId, groupId }));
  const deviceItems = [...chosenDevices].map((k) => k.split(':').map(Number)).filter(([tid]) => perimeterSet.has(tid))
    .map(([tenantId, deviceId]) => ({ tenantId, deviceId }));
  const chosenScopes = [...scopes].filter((s) => offered.has(s));

  const minV4 = options?.minPrefixV4 ?? 16;
  const minV6 = options?.minPrefixV6 ?? 48;
  const draftError = ipDraft.trim() ? ipEntryError(ipDraft, minV4, minV6) : null;
  const addIp = () => {
    const v = ipDraft.trim();
    if (!v || ipEntryError(v, minV4, minV6) !== null) return;
    if (!ipAllow.includes(v) && ipAllow.length < MCP_KEY_BOUNDS.ipAllowMax) setIpAllow([...ipAllow, v]);
    setIpDraft('');
  };
  const onIpKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',' || e.key === ' ') { e.preventDefault(); addIp(); }
  };

  const problems: string[] = [];
  if (options && !options.hasStepUpFactor) problems.push(t('accessKeys.create.needFactor') || 'Set up a second factor on your profile first.');
  if (!name.trim()) problems.push(t('accessKeys.create.needName') || 'Give the key a name.');
  if (perimeterTenants.length === 0) problems.push(t('accessKeys.create.needTenant') || 'Choose at least one tenant.');
  if (groupMode === 'list' && groupItems.length === 0) problems.push(t('accessKeys.create.needGroup') || 'Choose at least one group.');
  if (deviceMode === 'list' && deviceItems.length === 0) problems.push(t('accessKeys.create.needDevice') || 'Choose at least one device.');
  if (chosenScopes.length === 0) problems.push(t('accessKeys.create.needScope') || 'Choose at least one right.');
  if (ipForced && ipAllow.length === 0) problems.push(t('accessKeys.create.needIp') || 'An IP allow-list is required by your administrator.');

  const submit = async () => {
    if (problems.length > 0 || !options) return;
    const body: AccessKeyCreateBody = {
      name: name.trim(),
      expiresInDays: Math.min(Number(expiry), options.maxExpiryDays),
      scopes: chosenScopes,
      tenants: tenantChoice === 'all' ? { mode: 'all' } : { mode: 'list', ids: perimeterTenants },
      groups: groupMode === 'all' ? { mode: 'all' } : { mode: 'list', items: groupItems },
      devices: deviceMode === 'all' ? { mode: 'all' } : { mode: 'list', items: deviceItems },
      ipAllow,
    };
    setSaving(true);
    try {
      const r = await accessKeysApi.create(body);
      setCreated(r);
      onCreated();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err, t('accessKeys.create.failed') || 'The key could not be created.'));
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;
  if (created) return <CreatedStep created={created} onClose={onClose} />;

  const tenantName = (id: number) => tenantsById.get(id)?.name ?? `#${id}`;
  const sectionCls = 'space-y-2';
  const headCls = 'text-xs font-medium uppercase tracking-wider text-text-muted';

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="xl"
      title={t('accessKeys.create.title') || 'New access key'}
      icon={<KeyRound className="h-4 w-4 text-accent" />}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={submit} loading={saving} disabled={!options || problems.length > 0}
            title={problems[0]}>
            {t('accessKeys.create.submit') || 'Create the key'}
          </Button>
        </>
      )}
    >
      {optionsError ? <p className="text-sm text-red-400">{optionsError}</p>
        : !options ? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p> : (
          <div className="space-y-5">
            <p className="text-sm text-text-muted">
              {t('accessKeys.create.intro') || 'An AI agent (Claude Code…) uses this key to act as you, never with more rights than yours, re-checked at every call. Choose what it may reach and do. Sensitive actions always wait for your approval with a second factor.'}
            </p>
            {!options.hasStepUpFactor && (
              <div className="flex items-start gap-2 rounded-lg bg-amber-400/10 p-3 text-xs text-amber-300">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                <span>
                  {t('accessKeys.create.noFactor') || 'A key needs a second factor (an authenticator app, or your Obligate account) to approve its sensitive actions. Set one up on your profile.'}
                  {' '}<Link to="/profile" className="text-accent hover:underline">{t('accessKeys.create.toProfile') || 'Profile'}</Link>
                </span>
              </div>
            )}

            <div className="grid gap-4 sm:grid-cols-2">
              <Input
                label={t('accessKeys.create.name') || 'Name'}
                value={name}
                maxLength={MCP_KEY_BOUNDS.nameMax}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('accessKeys.create.namePlaceholder') || 'Claude Code: diagnosis'}
              />
              <div className="space-y-1">
                <span className="block text-sm font-medium text-text-secondary">{t('accessKeys.create.expiry') || 'Expires in'}</span>
                <SegmentedTabs<Expiry>
                  size="sm"
                  value={expiry}
                  onChange={setExpiry}
                  tabs={EXPIRIES.map((d) => ({ id: d, label: t('accessKeys.create.days', { count: Number(d) }) || `${d} days` }))}
                />
              </div>
            </div>

            {/* Tenants */}
            <section className={sectionCls}>
              <h3 className={headCls}>{t('accessKeys.create.tenants') || 'Tenants'}</h3>
              <SegmentedTabs<TenantChoice>
                size="sm"
                value={tenantChoice}
                onChange={setTenantChoice}
                tabs={[
                  { id: 'current', label: t('accessKeys.create.thisTenant') || 'This tenant', disabled: !currentAllowed },
                  { id: 'list', label: t('accessKeys.create.choose') || 'Choose' },
                  { id: 'all', label: t('accessKeys.create.allMyTenants') || 'All my tenants' },
                ]}
              />
              {tenantChoice === 'list' && (
                <ul className="max-h-48 overflow-y-auto rounded-lg bg-bg-tertiary/50">
                  {options.tenants.map((x) => (
                    <li key={x.tenantId}>
                      <label className="flex cursor-pointer items-center gap-2 px-3 py-1.5 text-sm hover:bg-bg-tertiary coarse:min-h-11">
                        <StyledCheckbox checked={chosenTenants.has(x.tenantId)} onChange={() => setChosenTenants(toggleIn(chosenTenants, x.tenantId))} />
                        <span className="flex-1 truncate text-text-primary">{x.name}</span>
                        {x.forceIpAllowList && <span className="text-[10px] text-amber-400">{t('accessKeys.create.ipForcedShort') || 'IP list required'}</span>}
                      </label>
                    </li>
                  ))}
                </ul>
              )}
              {tenantChoice === 'all' && (
                <p className="text-xs text-text-muted">
                  {isPlatformAdmin
                    ? (t('accessKeys.create.allTenantsAdmin') || 'As a platform administrator, this means EVERY tenant of the instance, including the tenants created later. The key never gets the global view: each call names one tenant.')
                    : (t('accessKeys.create.allTenantsHint') || 'Every tenant you can access at the time of each call, including the tenants you are given later.')}
                </p>
              )}
            </section>

            {/* Groups */}
            <section className={sectionCls}>
              <h3 className={headCls}>{t('accessKeys.create.groups') || 'Groups'}</h3>
              <SegmentedTabs<Mode>
                size="sm"
                value={groupMode}
                onChange={setGroupMode}
                tabs={[
                  { id: 'all', label: t('accessKeys.create.allGroups') || 'All groups' },
                  { id: 'list', label: t('accessKeys.create.choose') || 'Choose' },
                ]}
              />
              {groupMode === 'list' && (
                <>
                  <p className="text-xs text-text-muted">
                    {t('accessKeys.create.groupsHint') || 'A group includes its sub-groups. Devices outside these groups (or in no group) are outside the key; a tenant of the key without a chosen group shows no device.'}
                  </p>
                  {groupTree === null ? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
                    : groupsInPerimeter.length === 0 ? <p className="text-sm text-text-muted">{t('accessKeys.create.noGroups') || 'No group listed in this session for the chosen tenants.'}</p> : (
                      <ul className="max-h-60 overflow-y-auto rounded-lg bg-bg-tertiary/50">
                        {groupsInPerimeter.map(({ node, depth, ancestors }) => {
                          const k = gKey(node.tenantId, node.id);
                          const implied = ancestors.some((a) => chosenGroups.has(gKey(node.tenantId, a)));
                          return (
                            <li key={k}>
                              <label className={cn('flex items-center gap-2 py-1.5 pr-3 text-sm hover:bg-bg-tertiary coarse:min-h-11', !implied && 'cursor-pointer')}
                                style={{ paddingLeft: 12 + depth * 16 }}>
                                <StyledCheckbox checked={implied || chosenGroups.has(k)} disabled={implied} onChange={() => setChosenGroups(toggleIn(chosenGroups, k))} />
                                <FolderTree size={13} className="shrink-0 text-text-muted" />
                                <span className="flex-1 truncate text-text-primary">{anonymize(node.name)}</span>
                                {multiTenantPick && <span className="shrink-0 text-[10px] text-text-muted">{tenantName(node.tenantId)}</span>}
                              </label>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                </>
              )}
            </section>

            {/* Devices */}
            <section className={sectionCls}>
              <h3 className={headCls}>{t('accessKeys.create.devices') || 'Devices'}</h3>
              <SegmentedTabs<Mode>
                size="sm"
                value={deviceMode}
                onChange={setDeviceMode}
                tabs={[
                  { id: 'all', label: t('accessKeys.create.allDevices') || 'All devices' },
                  { id: 'list', label: t('accessKeys.create.choose') || 'Choose' },
                ]}
              />
              {deviceMode === 'list' && (
                <div className="rounded-lg bg-bg-tertiary/50">
                  <div className="flex items-center gap-2 px-3 py-2">
                    <Search className="h-3.5 w-3.5 shrink-0 text-text-muted" />
                    <div className="flex-1">
                      <Input value={deviceQuery} onChange={(e) => setDeviceQuery(e.target.value)} autoCapitalize="off" autoCorrect="off" spellCheck={false}
                        placeholder={t('accessKeys.create.deviceSearch') || 'Search a device'} aria-label={t('accessKeys.create.deviceSearch') || 'Search a device'} />
                    </div>
                    <span className="shrink-0 font-mono text-[11px] text-text-muted">{deviceItems.length}</span>
                  </div>
                  {devices === null ? <p className="px-3 py-2 text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
                    : devicesInPerimeter.length === 0 ? <p className="px-3 py-2 text-sm text-text-muted">{t('accessKeys.create.noDevices') || 'No device matches.'}</p> : (
                      <ul className="max-h-60 overflow-y-auto">
                        {devicesInPerimeter.slice(0, 500).map((d) => {
                          const k = gKey(d.tenantId, d.id);
                          return (
                            <li key={k}>
                              <label className="flex cursor-pointer items-center gap-2 px-3 py-1.5 text-sm hover:bg-bg-tertiary coarse:min-h-11">
                                <StyledCheckbox checked={chosenDevices.has(k)} onChange={() => setChosenDevices(toggleIn(chosenDevices, k))} />
                                <span className="flex-1 truncate text-text-primary">{anonymize(d.label)}</span>
                                {d.groupName && <span className="max-w-[140px] shrink-0 truncate text-[10px] text-text-muted">{anonymize(d.groupName)}</span>}
                                {multiTenantPick && <span className="shrink-0 text-[10px] text-text-muted">{tenantName(d.tenantId)}</span>}
                              </label>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                </div>
              )}
              {(groupMode === 'list' || deviceMode === 'list') && (
                <p className="text-xs text-text-muted">
                  {t('accessKeys.create.pickerHint') || 'Only the groups and devices this session lists are offered: switch tenant to pick in another tenant. With both groups and devices chosen, the key reaches the chosen devices that are in the chosen groups.'}
                </p>
              )}
            </section>

            {/* Scopes */}
            <section className={sectionCls}>
              <h3 className={headCls}>{t('accessKeys.create.scopes') || 'Rights'}</h3>
              <p className="text-xs text-text-muted">
                {t('accessKeys.create.scopesHint') || 'Only the rights you hold in a chosen tenant can be given. In each tenant the key never does more than you can do there.'}
              </p>
              {(['read', 'act'] as const).map((kind) => (
                <div key={kind}>
                  <p className="mb-1 mt-2 text-[11px] font-medium text-text-secondary">
                    {kind === 'read' ? (t('accessKeys.create.scopesRead') || 'Read') : (t('accessKeys.create.scopesAct') || 'Act')}
                  </p>
                  <ul className="rounded-lg bg-bg-tertiary/50">
                    {MCP_SCOPE_KEYS.filter((s) => MCP_SCOPES[s].kind === kind).map((s) => {
                      const can = offered.has(s);
                      return (
                        <li key={s}>
                          <label className={cn('flex items-start gap-2 px-3 py-1.5 text-sm coarse:min-h-11', can ? 'cursor-pointer hover:bg-bg-tertiary' : 'opacity-60')}>
                            <StyledCheckbox className="mt-0.5" checked={can && scopes.has(s)} disabled={!can} onChange={() => setScopes(toggleIn(scopes, s))} />
                            <span className="min-w-0 flex-1">
                              <span className="block text-text-primary">{scopeLabel(s)}</span>
                              <span className="block font-mono text-[10px] text-text-muted">
                                {s}{!can && ` · ${t('accessKeys.create.scopeNotHeld') || 'not held in the chosen tenants'}`}
                              </span>
                            </span>
                          </label>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </section>

            {/* IP allow-list */}
            <section className={sectionCls}>
              <h3 className={headCls}>{t('accessKeys.create.ipAllow') || 'Allowed addresses'}</h3>
              {ipForced && (
                <p className="flex items-center gap-1.5 text-xs text-amber-400">
                  <AlertTriangle size={12} />
                  {t('accessKeys.create.ipForced') || 'Required by your administrator for a chosen tenant.'}
                </p>
              )}
              {ipAllow.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {ipAllow.map((ip) => (
                    <span key={ip} className="inline-flex items-center gap-1 rounded-full bg-bg-tertiary px-2 py-0.5 font-mono text-xs text-text-primary">
                      {ip}
                      <IconButton size="xs" variant="plain" label={t('accessKeys.create.removeIp') || 'Remove'} icon={<X size={11} />}
                        onClick={() => setIpAllow(ipAllow.filter((x) => x !== ip))} />
                    </span>
                  ))}
                </div>
              )}
              <div className="flex items-start gap-2">
                <div className="flex-1">
                  <Input
                    value={ipDraft}
                    onChange={(e) => setIpDraft(e.target.value)}
                    onKeyDown={onIpKey}
                    onBlur={addIp}
                    autoCapitalize="off" autoCorrect="off" spellCheck={false}
                    placeholder="203.0.113.10, 198.51.100.0/24, 2001:db8::/48"
                    aria-label={t('accessKeys.create.ipAllow') || 'Allowed addresses'}
                    error={draftError === 'tooWide'
                      ? (t('accessKeys.create.ipTooWide', { v4: minV4, v6: minV6 }) || `Too wide: at least /${minV4} (IPv4) or /${minV6} (IPv6).`)
                      : draftError === 'invalid' ? (t('accessKeys.create.ipInvalid') || 'Not an address or a network.') : undefined}
                  />
                </div>
                <Button variant="secondary" size="sm" className="mt-0.5" onClick={addIp} disabled={!ipDraft.trim() || draftError !== null}>
                  {t('accessKeys.create.addIp') || 'Add'}
                </Button>
              </div>
              <p className="text-xs text-text-muted">
                {ipAllow.length === 0
                  ? (t('accessKeys.create.ipOpenNote') || 'Without an address, the key works from any IP. As long as one such key exists, the server cannot block an unknown address at once: it only counts failed attempts.')
                  : (t('accessKeys.create.ipListNote') || 'The key only works from these addresses.')}
              </p>
            </section>

            {problems.length > 0 && name.trim() !== '' && (
              <p className="text-xs text-text-muted">{problems[0]}</p>
            )}
          </div>
        )}
    </Modal>
  );
}

/** The token, shown once, and the command that connects Claude Code to it. */
function CreatedStep({ created, onClose }: { created: AccessKeyCreated; onClose: () => void }) {
  const { t } = useTranslation();
  const command = `claude mcp add --transport http obligarth ${window.location.origin}/mcp --header "Authorization: Bearer ${created.token}"`;
  const copy = (text: string) => {
    copyText(text).then((ok) => (ok ? toast.success(t('common.copied') || 'Copied!') : toast.error(t('common.error') || 'Error')));
  };
  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      closeOnBackdrop={false}
      closeOnEscape={false}
      title={t('accessKeys.created.title', { name: created.key.name }) || `Key « ${created.key.name} » created`}
      icon={<KeyRound className="h-4 w-4 text-accent" />}
      footer={<Button onClick={onClose}>{t('accessKeys.created.done') || 'I have copied it'}</Button>}
    >
      <div className="space-y-4">
        <div className="flex items-start gap-2 rounded-lg bg-amber-400/10 p-3 text-sm text-amber-300">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          {t('accessKeys.shownOnce') || 'Copy the key now: it is shown only once. Obligarth keeps only a fingerprint of it and cannot show it again.'}
        </div>
        <div className="space-y-1">
          <span className="block text-sm font-medium text-text-secondary">{t('accessKeys.created.token') || 'Key'}</span>
          <div className="flex items-center gap-2">
            <div className="flex-1"><Input readOnly value={created.token} className="font-mono text-xs" onFocus={(e) => e.currentTarget.select()} aria-label={t('accessKeys.created.token') || 'Key'} /></div>
            <IconButton label={t('common.copy') || 'Copy'} icon={<Copy className="h-4 w-4" />} variant="solid" size="lg" onClick={() => copy(created.token)} />
          </div>
        </div>
        <div className="space-y-1">
          <span className="block text-sm font-medium text-text-secondary">{t('accessKeys.created.command') || 'Connect Claude Code'}</span>
          <div className="flex items-start gap-2">
            <pre className="min-w-0 flex-1 whitespace-pre-wrap break-all rounded-md bg-bg-tertiary px-3 py-2 font-mono text-xs text-text-primary">{command}</pre>
            <IconButton label={t('common.copy') || 'Copy'} icon={<Copy className="h-4 w-4" />} variant="solid" size="lg" onClick={() => copy(command)} />
          </div>
          <p className="text-xs text-text-muted">
            {t('accessKeys.created.commandHint') || 'Run it in a terminal where Claude Code is installed. The agent then calls whoami to learn what this key lets it see and do.'}
          </p>
        </div>
      </div>
    </Modal>
  );
}
