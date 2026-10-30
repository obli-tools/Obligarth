import { useTranslation } from 'react-i18next';
import { Ban, Globe, KeyRound } from 'lucide-react';
import type { AccessKeyView } from '@obligarth/shared';
import { IconButton } from '@/components/common/IconButton';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { KEY_STATE_TONE, keyStateLabel, maskedToken, perimeterLines, relativeTime, revokeReasonLabel, scopeLabel } from './accessKeyLabels';

// The list of the user's access keys (docs: specs mcp-server §6.5), on the model of /devices: a borderless card, a
// header row, one row a key with its name, masked token, state, rights as pills, perimeter, IPs, expiry and last use.

export function RelativeDate({ iso, empty }: { iso: string | null | undefined; empty?: string }) {
  const r = relativeTime(iso);
  if (!r) return <span className="text-text-muted">{empty ?? '—'}</span>;
  return <time dateTime={iso ?? undefined} title={r.full}>{r.text}</time>;
}

export function ScopePills({ scopes }: { scopes: AccessKeyView['scopes'] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map((s) => (
        <span key={s} title={scopeLabel(s)} className="rounded-full bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent">{s}</span>
      ))}
    </div>
  );
}

interface Props {
  keys: AccessKeyView[];
  /** Revoke one key (absent: read only). */
  onRevoke?: (k: AccessKeyView) => void;
  /** A column with the owner (platform administration). */
  ownerOf?: (k: AccessKeyView) => string | null;
}

export function KeyList({ keys, onRevoke, ownerOf }: Props) {
  const { t } = useTranslation();
  return (
    <div className="overflow-hidden rounded-xl bg-bg-secondary">
      <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,3fr)_minmax(0,2fr)_auto] gap-3 bg-bg-tertiary/50 px-4 py-2 text-[10px] uppercase tracking-wider text-text-muted md:grid">
        <span>{t('accessKeys.list.key') || 'Key'}</span>
        <span>{t('accessKeys.list.perimeter') || 'Rights and perimeter'}</span>
        <span>{t('accessKeys.list.usage') || 'Expiry and use'}</span>
        <span className="w-8" />
      </div>
      <ul>
        {keys.map((k) => <KeyRow key={k.id} k={k} onRevoke={onRevoke} owner={ownerOf?.(k) ?? null} />)}
      </ul>
    </div>
  );
}

function KeyRow({ k, onRevoke, owner }: { k: AccessKeyView; onRevoke?: (k: AccessKeyView) => void; owner: string | null }) {
  const { t } = useTranslation();
  const p = perimeterLines(t, k);
  const lostNow = k.state === 'active' && k.effectiveNow.tenants.length === 0;
  return (
    <li className="grid gap-3 px-4 py-3 text-sm transition-colors hover:bg-bg-tertiary md:grid-cols-[minmax(0,2fr)_minmax(0,3fr)_minmax(0,2fr)_auto]">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <KeyRound size={14} className="shrink-0 text-text-muted" />
          <span className="truncate font-medium text-text-primary">{k.name}</span>
          <StateBadge tone={KEY_STATE_TONE[k.state]} label={keyStateLabel(k.state)} />
        </div>
        <p className="truncate font-mono text-[11px] text-text-muted">{maskedToken(k.id)}</p>
        {owner && <p className="truncate text-[11px] text-text-secondary">{owner}</p>}
        {k.revokeReason && <p className="text-[11px] text-red-400">{revokeReasonLabel(k.revokeReason)}</p>}
        {lostNow && (
          <p className="text-[11px] text-amber-400">{t('accessKeys.list.noTenantNow') || 'No tenant reachable now (rights or tenants lost).'}</p>
        )}
      </div>
      <div className="min-w-0 space-y-1.5">
        <ScopePills scopes={k.scopes} />
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2 gap-y-0.5 text-[11px]">
          <dt className="text-text-muted">{t('accessKeys.list.tenants') || 'Tenants'}</dt>
          <dd className="truncate text-text-secondary" title={p.tenants}>{p.tenants}</dd>
          <dt className="text-text-muted">{t('accessKeys.list.groups') || 'Groups'}</dt>
          <dd className="truncate text-text-secondary" title={p.groups}>{p.groups}</dd>
          <dt className="text-text-muted">{t('accessKeys.list.devices') || 'Devices'}</dt>
          <dd className="truncate text-text-secondary" title={p.devices}>{p.devices}</dd>
          {k.excludedTenants.length > 0 && (
            <>
              <dt className="text-text-muted">{t('accessKeys.list.excluded') || 'Excluded'}</dt>
              <dd className="truncate text-amber-400">
                {t('accessKeys.list.excludedTenants', { count: k.excludedTenants.length }) || `${k.excludedTenants.length} tenant(s), by their managers`}
              </dd>
            </>
          )}
        </dl>
      </div>
      <div className="min-w-0 space-y-0.5 text-[11px] text-text-secondary">
        <p className="flex flex-wrap items-center gap-1">
          <Globe size={11} className="text-text-muted" />
          {k.ipAllow.length === 0
            ? <span className="text-text-muted">{t('accessKeys.list.anyIp') || 'Any IP'}</span>
            : <span className="break-all font-mono" title={k.ipAllow.join(', ')}>{k.ipAllow.slice(0, 3).join(', ')}{k.ipAllow.length > 3 && ` +${k.ipAllow.length - 3}`}</span>}
        </p>
        <p>
          <span className="text-text-muted">{k.state === 'expired' ? (t('accessKeys.list.expired') || 'Expired') : (t('accessKeys.list.expires') || 'Expires')} </span>
          <RelativeDate iso={k.expiresAt} />
        </p>
        <p>
          <span className="text-text-muted">{t('accessKeys.list.lastUsed') || 'Last used'} </span>
          <RelativeDate iso={k.lastUsedAt} empty={t('common.never') || 'Never'} />
          {k.lastUsedIp && <span className="font-mono text-text-muted"> · {k.lastUsedIp}</span>}
        </p>
        {k.revokedAt && (
          <p><span className="text-text-muted">{t('accessKeys.list.revoked') || 'Revoked'} </span><RelativeDate iso={k.revokedAt} /></p>
        )}
      </div>
      <div className="flex items-start justify-end">
        {onRevoke && k.state === 'active' && (
          <IconButton label={t('accessKeys.list.revoke') || 'Revoke'} variant="danger" icon={<Ban className="h-4 w-4" />} onClick={() => onRevoke(k)} />
        )}
      </div>
    </li>
  );
}
