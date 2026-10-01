import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { KeyRound, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import type { VaultOperation, VaultStatus } from '@obligarth/shared';
import { vaultApi, type EscrowEventKind } from '@/api/vault.api';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { useTenantStore } from '@/store/tenantStore';

// The server's vault of secrets (platform administrators, master tenant):
// state, escrow events, key rotations, operations. Fingerprints and counts
// only: no key and no secret ever reaches the browser.

function when(iso: string | null | undefined): string {
 if (!iso) return '—';
 const d = new Date(iso);
 return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

function errorText(err: unknown, fallback: string): string {
 const e = err as { response?: { data?: { error?: string } } };
 return e?.response?.data?.error || fallback;
}

export function VaultPanel() {
 const { t } = useTranslation();
 const { tenants } = useTenantStore();
 const [status, setStatus] = useState<VaultStatus | null>(null);
 const [ops, setOps] = useState<VaultOperation[]>([]);
 const [loading, setLoading] = useState(true);
 const [busy, setBusy] = useState<string | null>(null);

 const [escrowKind, setEscrowKind] = useState<EscrowEventKind>('confirmation');
 const [escrowServer, setEscrowServer] = useState('');
 const [escrowEdge, setEscrowEdge] = useState('');
 const [escrowNote, setEscrowNote] = useState('');
 const [kekReason, setKekReason] = useState('');
 const [dekTenant, setDekTenant] = useState<string>('instance');
 const [dekReason, setDekReason] = useState('');

 const load = async () => {
 setLoading(true);
 try {
 const [s, o] = await Promise.all([vaultApi.status(), vaultApi.operations(undefined, 50)]);
 setStatus(s);
 setOps(o);
 } catch (err) {
 toast.error(errorText(err, t('vault.loadFailed') || 'Could not load the state of the vault'));
 } finally {
 setLoading(false);
 }
 };

 useEffect(() => { void load(); }, []);

 const submitEscrow = async (e: FormEvent) => {
 e.preventDefault();
 setBusy('escrow');
 try {
 await vaultApi.recordEscrowEvent({
 kind: escrowKind,
 kekIds: { server: escrowServer.trim(), edge: escrowEdge.trim() || null },
 note: escrowNote.trim() || undefined,
 });
 toast.success(t('vault.escrow.recorded') || 'Escrow event recorded');
 setEscrowNote('');
 await load();
 } catch (err) {
 toast.error(errorText(err, t('vault.escrow.failed') || 'Escrow event not recorded'));
 } finally {
 setBusy(null);
 }
 };

 const submitKek = async (e: FormEvent) => {
 e.preventDefault();
 setBusy('kek');
 try {
 const r = await vaultApi.requestKekRotation(kekReason.trim());
 toast.success(`${t('vault.kek.requested') || 'KEK rotation requested: another platform administrator must approve it'} (${r.operationId})`);
 setKekReason('');
 await load();
 } catch (err) {
 toast.error(errorText(err, t('vault.kek.failed') || 'KEK rotation not requested'));
 } finally {
 setBusy(null);
 }
 };

 const submitDek = async (e: FormEvent) => {
 e.preventDefault();
 setBusy('dek');
 try {
 await vaultApi.requestDekRotation(dekTenant === 'instance' ? null : Number(dekTenant), dekReason.trim());
 toast.success(t('vault.dek.requested') || 'Data key rotation started');
 setDekReason('');
 await load();
 } catch (err) {
 toast.error(errorText(err, t('vault.dek.failed') || 'Data key rotation not started'));
 } finally {
 setBusy(null);
 }
 };

 if (loading && !status) {
 return <p className="text-sm text-text-muted">{t('common.loading') || 'Loading…'}</p>;
 }
 if (!status) return null;

 const covered = status.escrow.coversCurrentKek;
 const remaining = Object.entries(status.backfill.remaining).filter(([, n]) => n > 0);

 return (
 <div className="space-y-6">
 <div className="flex items-start justify-between gap-3">
 <div>
 <h2 className="text-lg font-semibold text-text-primary">{t('vault.title') || 'Vault of secrets'}</h2>
 <p className="text-sm text-text-muted">
 {t('vault.description') || 'Encryption keys of the stored secrets. No key and no secret is ever shown here.'}
 </p>
 </div>
 <Button size="sm" variant="secondary" onClick={() => void load()} loading={loading}>
 <RefreshCw size={14} className="mr-1.5" />
 {t('vault.refresh') || 'Refresh'}
 </Button>
 </div>

 {!covered && (
 <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-300">
 <ShieldAlert size={18} className="shrink-0 mt-0.5" />
 <span>{t('vault.escrow.missing') || 'The current key-encryption key is not escrowed: escrow it (vault escrow split) and record the confirmation below. Apple secrets stay refused until then.'}</span>
 </div>
 )}

 <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
 <Card title={t('vault.status.kek') || 'Key-encryption key (KEK)'}>
 <Line label={t('vault.status.provider') || 'Provider'} value={status.provider} />
 <Line label="kek_id" value={<code className="text-xs">{status.kekId}</code>} />
 <Line label={t('vault.status.lastKekRotation') || 'Last rotation'} value={when(status.lastKekRotationAt)} />
 </Card>
 <Card title={t('vault.status.keys') || 'Data keys (DEK)'}>
 <Line label={t('vault.status.instanceKey') || 'Instance key'} value={status.instanceDek ? `v${status.instanceDek.version}` : '—'} />
 <Line label={t('vault.status.activeTenantKeys') || 'Active tenant keys'} value={status.tenantKeys.active} />
 <Line label={t('vault.status.retired') || 'Retired / destroyed'} value={`${status.tenantKeys.retired} / ${status.tenantKeys.destroyed}`} />
 <Line label={t('vault.status.scheduled') || 'Scheduled for destruction'} value={status.tenantKeys.scheduled} />
 <Line label={t('vault.status.withoutKey') || 'Tenants without a key'} value={status.tenantKeys.tenantsWithoutKey} />
 </Card>
 <Card title={t('vault.status.escrow') || 'Escrow'}>
 <Line label={t('vault.status.confirmed') || 'Confirmed'} value={when(status.escrow.confirmedAt)} />
 <Line label={t('vault.status.tested') || 'Last test'} value={when(status.escrow.lastTestAt)} />
 <Line
 label={t('vault.status.covers') || 'Covers the current KEK'}
 value={covered
 ? <span className="inline-flex items-center gap-1 text-status-up"><ShieldCheck size={14} />{t('vault.yes') || 'Yes'}</span>
 : <span className="text-status-down">{t('vault.no') || 'No'}</span>}
 />
 </Card>
 <Card title={t('vault.status.backfill') || 'Inherited secrets'}>
 <Line
 label={t('vault.status.backfillState') || 'Moved into the vault'}
 value={status.backfill.complete ? (t('vault.status.complete') || 'Complete') : (t('vault.status.incomplete') || 'Values left in place')}
 />
 {remaining.map(([col, n]) => <Line key={col} label={col} value={n} />)}
 <Line label={t('vault.status.lastRun') || 'Last run'} value={when(status.backfill.lastRunAt)} />
 </Card>
 <Card title={t('vault.status.operations') || 'Operations'}>
 <Line label={t('vault.status.running') || 'Running'} value={status.operations.running} />
 <Line label={t('vault.status.failed') || 'Failed'} value={status.operations.failed} />
 </Card>
 </div>

 <form onSubmit={submitEscrow} className="rounded-lg bg-bg-secondary p-4 space-y-3">
 <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wide">{t('vault.escrow.title') || 'Escrow event'}</h3>
 <p className="text-xs text-text-muted">{t('vault.escrow.help') || 'After the ceremony (2 shares out of 3), record what was done, with the kek_id the escrow tool printed from the shares (never copied from this page: the server checks it against the current key). A second factor is asked.'}</p>
 <div className="grid gap-3 sm:grid-cols-2">
 <div className="space-y-1">
 <label className="block text-sm font-medium text-text-secondary">{t('vault.escrow.kind') || 'Event'}</label>
 <select
 value={escrowKind}
 onChange={(e) => setEscrowKind(e.target.value as EscrowEventKind)}
 className="w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent"
 >
 <option value="confirmation">{t('vault.escrow.confirmation') || 'Escrow confirmed'}</option>
 <option value="test">{t('vault.escrow.test') || 'Annual test of the shares'}</option>
 <option value="old_shares_destroyed">{t('vault.escrow.oldShares') || 'Old shares destroyed'}</option>
 </select>
 </div>
 <Input label={t('vault.escrow.serverKekId') || 'kek_id of the server, as printed from the shares (16 hex)'} value={escrowServer}
 onChange={(e) => setEscrowServer(e.target.value)} required pattern="[0-9a-f]{16}" autoCapitalize="off" spellCheck={false} />
 <Input label={t('vault.escrow.edgeKekId') || 'kek_id of apple-edge (optional)'} value={escrowEdge}
 onChange={(e) => setEscrowEdge(e.target.value)} pattern="[0-9a-f]{16}" autoCapitalize="off" spellCheck={false} />
 <Input label={t('vault.escrow.note') || 'Note (no secret)'} value={escrowNote} maxLength={500}
 onChange={(e) => setEscrowNote(e.target.value)} />
 </div>
 <Button type="submit" size="sm" loading={busy === 'escrow'}>{t('vault.escrow.record') || 'Record'}</Button>
 </form>

 <div className="grid gap-3 lg:grid-cols-2">
 <form onSubmit={submitKek} className="rounded-lg bg-bg-secondary p-4 space-y-3">
 <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wide">{t('vault.kek.title') || 'Rotate the KEK'}</h3>
 <p className="text-xs text-text-muted">{t('vault.kek.help') || 'Another platform administrator approves it; the rotation is then run on the host with the server stopped (vault kek-rotate), within 24 hours.'}</p>
 <Input label={t('vault.reason') || 'Reason'} value={kekReason} onChange={(e) => setKekReason(e.target.value)} required minLength={3} maxLength={500} />
 <Button type="submit" size="sm" variant="secondary" loading={busy === 'kek'}>{t('vault.kek.request') || 'Request the rotation'}</Button>
 </form>
 <form onSubmit={submitDek} className="rounded-lg bg-bg-secondary p-4 space-y-3">
 <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wide">{t('vault.dek.title') || 'Rotate a data key'}</h3>
 <p className="text-xs text-text-muted">{t('vault.dek.help') || 'After an incident only: every secret of the key is resealed in the background. A second factor is asked.'}</p>
 <div className="space-y-1">
 <label className="block text-sm font-medium text-text-secondary">{t('vault.dek.key') || 'Key'}</label>
 <select
 value={dekTenant}
 onChange={(e) => setDekTenant(e.target.value)}
 className="w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent"
 >
 <option value="instance">{t('vault.dek.instance') || 'Instance key'}</option>
 {tenants.map((tn) => <option key={tn.id} value={String(tn.id)}>{tn.name}</option>)}
 </select>
 </div>
 <Input label={t('vault.reason') || 'Reason'} value={dekReason} onChange={(e) => setDekReason(e.target.value)} required minLength={3} maxLength={500} />
 <Button type="submit" size="sm" variant="secondary" loading={busy === 'dek'}>{t('vault.dek.request') || 'Rotate'}</Button>
 </form>
 </div>

 <div className="rounded-lg bg-bg-secondary">
 <h3 className="px-4 pt-4 text-sm font-semibold text-text-secondary uppercase tracking-wide">{t('vault.history') || 'Operations'}</h3>
 {ops.length === 0 ? (
 <p className="p-4 text-sm text-text-muted">{t('vault.noOperations') || 'No operation yet.'}</p>
 ) : (
 <div className="overflow-x-auto">
 <table className="w-full text-sm">
 <thead>
 <tr className="text-left text-text-muted">
 <th className="px-4 py-2 font-medium">{t('vault.op.date') || 'Date'}</th>
 <th className="px-4 py-2 font-medium">{t('vault.op.kind') || 'Operation'}</th>
 <th className="px-4 py-2 font-medium">{t('vault.op.state') || 'State'}</th>
 <th className="px-4 py-2 font-medium">{t('vault.op.target') || 'Key'}</th>
 <th className="px-4 py-2 font-medium">Id</th>
 </tr>
 </thead>
 <tbody className="divide-y divide-border">
 {ops.map((o) => (
 <tr key={o.id}>
 <td className="px-4 py-2 whitespace-nowrap">{when(o.createdAt)}</td>
 <td className="px-4 py-2">{t(`vault.kind.${o.kind}`) || o.kind}</td>
 <td className="px-4 py-2">{t(`vault.state.${o.state}`) || o.state}</td>
 <td className="px-4 py-2">{o.tenantId === null ? (o.kind === 'dek_rotation' ? (t('vault.dek.instance') || 'Instance key') : '—') : `#${o.tenantId}`}</td>
 <td className="px-4 py-2"><code className="text-xs">{o.id.slice(0, 8)}</code></td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 )}
 </div>
 </div>
 );
}

function Card({ title, children }: { title: string; children: ReactNode }) {
 return (
 <div className="rounded-lg bg-bg-secondary p-4">
 <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-secondary">
 <KeyRound size={14} className="text-accent" />
 {title}
 </div>
 <dl className="space-y-1">{children}</dl>
 </div>
 );
}

function Line({ label, value }: { label: string; value: ReactNode }) {
 return (
 <div className="flex items-center justify-between gap-3 text-sm">
 <dt className="text-text-muted">{label}</dt>
 <dd className="text-text-primary text-right">{value}</dd>
 </div>
 );
}
