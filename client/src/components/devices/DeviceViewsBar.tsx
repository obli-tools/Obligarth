import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import {
  AlertTriangle, Bookmark, BookmarkPlus, Check, ChevronDown, Link2, Loader2, Lock, Pencil, RefreshCw, RotateCcw, Save, Share2, Star,
  StarOff, Trash2, Users, X,
} from 'lucide-react';
import { DEVICE_VIEW_LIMITS, type DeviceView, type DeviceViewDefinition } from '@obligarth/shared';
import { deviceViewsApi } from '@/api/deviceViews.api';
import { ActionMenu, type ActionMenuItem } from '@/components/common/ActionMenu';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { apiErrorCode, apiErrorMessage } from '@/utils/apiError';
import { differsFrom } from './deviceViewDefinition';

// =============================================================================
// The saved views of the inventory (P0-5 §6, D6): choose a view (its filters, advanced filter, group, sort and columns
// replace those of the list), save the list as a new view, update the view with the list, rename, share with the
// members of the tenant or stop sharing, set as default, copy its link (/devices?view=<uuid>), go back to the view as
// saved, close it, delete it. A view stays chosen while the list is changed by hand ("modified"). The default view
// and a view of the link are applied by the table once the views are loaded (`pending`): loaded, not failed to load
// (a failure keeps the view chosen and the link, and offers to try again). A view gone since (404 deviceViewNotFound
// on a change) reloads the views, which lets it go.
// =============================================================================

export type PendingView = { kind: 'uuid'; uuid: string } | { kind: 'default' } | null;

interface DeviceViewsBarProps {
  /** The definition of the current state of the list. */
  current: DeviceViewDefinition;
  activeUuid: string | null;
  /** A view chosen: `apply` replaces the state of the list with its definition (false: the list already is it). */
  onSelect: (view: DeviceView, apply: boolean) => void;
  /** No view any more, the list kept as it is. */
  onDetach: () => void;
  /** No view any more, the list back to its defaults. */
  onReset: () => void;
  /** A view to apply once the views are loaded (a link's ?view=, the default view at the opening). */
  pending: PendingView;
  onPendingDone: () => void;
  /** Phone toolbar: the bar takes the whole width. */
  compact?: boolean;
}

type Editing = { mode: 'create' } | { mode: 'rename'; view: DeviceView } | null;

export function DeviceViewsBar({ current, activeUuid, onSelect, onDetach, onReset, pending, onPendingDone, compact = false }: DeviceViewsBarProps) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  // null until the views are loaded once (a failure keeps the last list loaded, or null).
  const [views, setViews] = useState<DeviceView[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<Editing>(null);

  const reload = useCallback(async (): Promise<void> => {
    try {
      const list = await deviceViewsApi.list();
      setViews(list);
      setLoadFailed(false);
    } catch (err) {
      toast.error(apiErrorMessage(err));
      setLoadFailed(true);
    }
  }, []);
  useEffect(() => { void reload(); }, [reload]);

  // The pending view (link, default), once the views are known.
  const pendingRef = useRef(pending);
  pendingRef.current = pending;
  useEffect(() => {
    const p = pendingRef.current;
    if (!views || !p) return;
    if (p.kind === 'uuid') {
      const v = views.find((x) => x.uuid === p.uuid.toLowerCase());
      if (v) onSelect(v, true);
      else { toast.error(t('deviceViews.notFound') || 'This view does not exist, or is not shared with you.'); onDetach(); }
    } else {
      const v = views.find((x) => x.isDefault);
      if (v) onSelect(v, true);
    }
    onPendingDone();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [views, pending]);

  const active = activeUuid && views ? views.find((v) => v.uuid === activeUuid) ?? null : null;
  // The chosen view was deleted or unshared since: no view any more, the list kept.
  useEffect(() => {
    if (views && activeUuid && !pending && !views.some((v) => v.uuid === activeUuid)) onDetach();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [views, activeUuid, pending]);

  const modified = !!active && differsFrom(current, active.definition);
  const tooLarge = JSON.stringify(current).length > DEVICE_VIEW_LIMITS.definitionMaxBytes;

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
    } catch (err) {
      toast.error(apiErrorMessage(err), { duration: 7000 });
      // Deleted or unshared since: the views again (the chosen one goes, the list kept).
      if (apiErrorCode(err) === 'deviceViewNotFound') await reload();
    } finally { setBusy(false); }
  };

  const update = (view: DeviceView) => run(async () => {
    const saved = await deviceViewsApi.update(view.id, { definition: current });
    await reload();
    onSelect(saved, false);
    toast.success(t('deviceViews.updated') || 'View updated');
  });
  const toggleShare = (view: DeviceView) => run(async () => {
    if (view.shared && !(await confirm({
      title: t('deviceViews.unshareTitle') || 'Stop sharing this view?',
      message: t('deviceViews.unshareMessage') || 'The other members of the tenant will no longer see it; it stops being their default view.',
      confirmLabel: t('deviceViews.unshare') || 'Stop sharing',
    }))) return;
    await deviceViewsApi.update(view.id, { shared: !view.shared });
    await reload();
    toast.success(view.shared ? (t('deviceViews.unshared') || 'The view is private again') : (t('deviceViews.sharedDone') || 'The view is shared with the members of the tenant'));
  });
  const toggleDefault = (view: DeviceView) => run(async () => {
    await deviceViewsApi.setDefault(view.isDefault ? null : view.id);
    await reload();
    toast.success(view.isDefault ? (t('deviceViews.defaultRemoved') || 'No default view any more') : (t('deviceViews.defaultSet') || 'Default view set'));
  });
  const remove = (view: DeviceView) => run(async () => {
    if (!(await confirm({
      title: t('deviceViews.deleteTitle') || 'Delete this view?',
      message: view.shared
        ? (t('deviceViews.deleteSharedMessage', { name: view.name }) || `"${view.name}" is shared: it disappears for every member of the tenant.`)
        : (t('deviceViews.deleteMessage', { name: view.name }) || `"${view.name}" will be deleted.`),
      danger: true,
    }))) return;
    await deviceViewsApi.remove(view.id);
    await reload();
    onDetach();
    toast.success(t('deviceViews.deleted') || 'View deleted');
  });
  const copyLink = async (view: DeviceView) => {
    const url = `${window.location.origin}/devices?view=${view.uuid}`;
    try {
      await navigator.clipboard.writeText(url);
      toast.success(t('deviceViews.linkCopied') || 'Link copied');
    } catch {
      toast(url, { duration: 10_000 });
    }
  };

  const ownerLine = (v: DeviceView): string => {
    const kind = !v.shared ? (t('deviceViews.private') || 'Private')
      : v.mine ? (t('deviceViews.sharedByYou') || 'Shared by you')
        : (t('deviceViews.sharedBy', { owner: v.owner.name ?? '—' }) || `Shared by ${v.owner.name ?? '—'}`);
    return v.isDefault ? `${kind} · ${t('deviceViews.default') || 'Default'}` : kind;
  };

  const mine = (views ?? []).filter((v) => v.mine);
  const others = (views ?? []).filter((v) => !v.mine);
  const pickItems: ActionMenuItem[] = [
    {
      key: 'none', label: t('deviceViews.none') || 'No view', description: t('deviceViews.noneHint') || 'Back to the default filters',
      icon: !active ? <Check className="h-4 w-4 text-accent" /> : <X className="h-4 w-4" />, onClick: onReset,
    },
    ...[...mine, ...others].map((v, i): ActionMenuItem => ({
      key: `v-${v.uuid}`,
      label: v.name,
      description: ownerLine(v),
      separator: i === 0 || (i === mine.length && mine.length > 0),
      icon: active?.uuid === v.uuid ? <Check className="h-4 w-4 text-accent" />
        : v.isDefault ? <Star className="h-4 w-4 text-amber-400" />
          : v.shared ? <Users className="h-4 w-4" /> : <Lock className="h-4 w-4" />,
      onClick: () => onSelect(v, true),
    })),
    ...(views && views.length === 0 ? [{ key: 'empty', label: t('deviceViews.empty') || 'No saved view yet', onClick: () => {}, disabled: true, separator: true }] : []),
    ...(views === null && !loadFailed ? [{
      key: 'loading', icon: <Loader2 className="h-4 w-4 animate-spin" />, label: t('deviceViews.loading') || 'Loading the views…',
      onClick: () => {}, disabled: true, separator: true,
    }] : []),
    ...(loadFailed ? [{
      key: 'retry', icon: views === null ? <AlertTriangle className="h-4 w-4 text-red-400" /> : <RefreshCw className="h-4 w-4" />,
      label: t('deviceViews.retry') || 'Try again',
      description: t('deviceViews.loadFailed') || 'The views could not be loaded.',
      onClick: () => { void reload(); }, separator: true,
    }] : []),
  ];

  const actionItems: ActionMenuItem[] = [
    { key: 'update', icon: <Save className="h-4 w-4" />, label: t('deviceViews.update') || 'Save the changes in the view', onClick: () => active && void update(active),
      hidden: !active || !active.editable || !modified, disabled: tooLarge },
    { key: 'create', icon: <BookmarkPlus className="h-4 w-4" />, label: t('deviceViews.saveAs') || 'Save as a new view…', onClick: () => setEditing({ mode: 'create' }), disabled: tooLarge },
    { key: 'revert', icon: <RotateCcw className="h-4 w-4" />, label: t('deviceViews.revert') || 'Back to the view as saved', onClick: () => active && onSelect(active, true), hidden: !active || !modified },
    { key: 'rename', icon: <Pencil className="h-4 w-4" />, label: t('deviceViews.rename') || 'Rename…', onClick: () => active && setEditing({ mode: 'rename', view: active }), hidden: !active?.editable, separator: true },
    { key: 'share', icon: <Share2 className="h-4 w-4" />, label: active?.shared ? (t('deviceViews.unshare') || 'Stop sharing') : (t('deviceViews.share') || 'Share with the tenant'),
      description: active?.shared ? undefined : (t('deviceViews.shareHint') || 'Every member sees it; the list stays limited to what each one may see.'), wrapDescription: true,
      onClick: () => active && void toggleShare(active), hidden: !active?.editable },
    { key: 'default', icon: active?.isDefault ? <StarOff className="h-4 w-4" /> : <Star className="h-4 w-4" />,
      label: active?.isDefault ? (t('deviceViews.unsetDefault') || 'Stop opening the list on this view') : (t('deviceViews.setDefault') || 'Open the list on this view'),
      onClick: () => active && void toggleDefault(active), hidden: !active },
    { key: 'link', icon: <Link2 className="h-4 w-4" />, label: t('deviceViews.copyLink') || 'Copy the link', onClick: () => active && void copyLink(active), hidden: !active },
    { key: 'close', icon: <X className="h-4 w-4" />, label: t('deviceViews.close') || 'Close the view', onClick: onReset, hidden: !active, separator: true },
    { key: 'delete', icon: <Trash2 className="h-4 w-4" />, label: t('deviceViews.delete') || 'Delete the view…', onClick: () => active && void remove(active), hidden: !active?.editable, danger: true },
  ];

  const label = active ? active.name : (t('deviceViews.none') || 'No view');
  return (
    <div className={clsx('flex min-w-0 items-center gap-2', compact ? 'w-full' : 'mb-3')}>
      <ActionMenu
        items={pickItems}
        label={t('deviceViews.title') || 'Views'}
        sheetTitle={t('deviceViews.title') || 'Views'}
        align="start"
        menuClassName="w-72"
        trigger={(p) => (
          <button {...p} type="button" disabled={busy}
            aria-label={`${t('deviceViews.title') || 'Views'}: ${label}`}
            className={clsx('flex min-w-0 items-center gap-1.5 rounded-lg px-2.5 py-2 text-xs transition-colors coarse:min-h-10',
              compact && 'flex-1',
              active ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:bg-bg-active hover:text-text-primary')}>
            <Bookmark className="h-3.5 w-3.5 shrink-0" />
            <span className="shrink-0 text-[10px] uppercase tracking-wider opacity-80">{t('deviceViews.title') || 'Views'}</span>
            <span className={clsx('truncate font-medium', active && 'text-text-primary')}>{label}</span>
            {active?.shared && <Users className="h-3 w-3 shrink-0 opacity-70" aria-label={t('deviceViews.shared') || 'Shared'} />}
            <ChevronDown className="ml-auto h-3.5 w-3.5 shrink-0" />
          </button>
        )}
      />
      {modified && (
        <span className="shrink-0 rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-medium text-amber-400" title={t('deviceViews.modifiedHint') || 'The list differs from the view as saved'}>
          {t('deviceViews.modified') || 'Modified'}
        </span>
      )}
      {active?.editable && modified ? (
        <button type="button" onClick={() => void update(active)} disabled={busy || tooLarge}
          title={t('deviceViews.update') || 'Save the changes in the view'} aria-label={t('deviceViews.update') || 'Save the changes in the view'}
          className="flex shrink-0 items-center gap-1.5 rounded-lg bg-accent px-2.5 py-2 text-xs text-white hover:bg-accent/80 disabled:opacity-50 coarse:min-h-10">
          <Save className="h-3.5 w-3.5" />
          {!compact && <span>{t('deviceViews.save') || 'Save'}</span>}
        </button>
      ) : (
        <button type="button" onClick={() => setEditing({ mode: 'create' })} disabled={busy || tooLarge}
          title={t('deviceViews.saveAs') || 'Save as a new view…'} aria-label={t('deviceViews.saveAs') || 'Save as a new view…'}
          className="flex shrink-0 items-center gap-1.5 rounded-lg bg-bg-tertiary px-2.5 py-2 text-xs text-text-muted hover:bg-bg-active hover:text-text-primary disabled:opacity-50 coarse:min-h-10">
          <BookmarkPlus className="h-3.5 w-3.5" />
          {!compact && <span>{t('deviceViews.saveShort') || 'Save the view'}</span>}
        </button>
      )}
      <ActionMenu items={actionItems} label={t('deviceViews.actions') || 'Actions of the view'} triggerClassName="coarse:min-h-10 coarse:min-w-10" disabled={busy} />

      <ViewEditDialog
        editing={editing}
        onClose={() => setEditing(null)}
        onSubmit={(values) => run(async () => {
          if (editing?.mode === 'rename') {
            const saved = await deviceViewsApi.update(editing.view.id, { name: values.name, description: values.description });
            await reload();
            onSelect(saved, false);
            toast.success(t('deviceViews.renamed') || 'View renamed');
          } else {
            const created = await deviceViewsApi.create({ name: values.name, description: values.description, shared: values.shared, definition: current });
            // The view exists from here: chosen and the dialog closed whatever comes next (a second save would answer
            // deviceViewNameTaken for a view the menu does not show).
            let defaultError: unknown = null;
            if (values.makeDefault) {
              try { await deviceViewsApi.setDefault(created.id); } catch (err) { defaultError = err; }
            }
            setEditing(null);
            await reload();
            onSelect(defaultError ? created : { ...created, isDefault: values.makeDefault }, false);
            if (defaultError) {
              const error = apiErrorMessage(defaultError);
              toast.error(t('deviceViews.createdNotDefault', { error }) || `View saved, but not set as the default view: ${error}`, { duration: 7000 });
            } else {
              toast.success(t('deviceViews.created') || 'View saved');
            }
            return;
          }
          setEditing(null);
        })}
        busy={busy}
      />
    </div>
  );
}

function ViewEditDialog({ editing, onClose, onSubmit, busy }: {
  editing: Editing;
  onClose: () => void;
  onSubmit: (values: { name: string; description: string | null; shared: boolean; makeDefault: boolean }) => void;
  busy: boolean;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [shared, setShared] = useState(false);
  const [makeDefault, setMakeDefault] = useState(false);
  useEffect(() => {
    if (!editing) return;
    setName(editing.mode === 'rename' ? editing.view.name : '');
    setDescription(editing.mode === 'rename' ? editing.view.description ?? '' : '');
    setShared(false);
    setMakeDefault(false);
  }, [editing]);
  const trimmed = name.trim();
  const fieldCls = 'mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent/50 coarse:min-h-10';
  const submit = () => { if (trimmed) onSubmit({ name: trimmed, description: description.trim() || null, shared, makeDefault }); };
  return (
    <Modal
      open={editing !== null}
      onClose={() => { if (!busy) onClose(); }}
      size="sm"
      phoneLayout="sheet"
      icon={<Bookmark className="h-4 w-4 text-accent" />}
      title={editing?.mode === 'rename' ? (t('deviceViews.renameTitle') || 'Rename the view') : (t('deviceViews.createTitle') || 'Save the list as a view')}
      bodyClassName="px-4 py-4 space-y-3"
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={submit} loading={busy} disabled={busy || !trimmed}>{t('common.save') || 'Save'}</Button>
        </>
      )}
    >
      <form onSubmit={(e) => { e.preventDefault(); submit(); }} className="space-y-3">
        <label className="block">
          <span className="text-xs text-text-muted">{t('deviceViews.name') || 'Name'}</span>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={DEVICE_VIEW_LIMITS.nameMax} autoFocus className={fieldCls} />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('deviceViews.description') || 'Description (optional)'}</span>
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} maxLength={DEVICE_VIEW_LIMITS.descriptionMax} rows={2} className={fieldCls} />
        </label>
        {editing?.mode === 'create' && (
          <>
            <p className="text-[11px] text-text-muted">{t('deviceViews.createHint') || 'The view keeps the filters, the advanced filter, the group, the sort and the columns of the list.'}</p>
            <label className="flex items-start gap-2 text-sm text-text-primary">
              <input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} className="mt-0.5 accent-accent" />
              <span>
                {t('deviceViews.shareOption') || 'Share with the members of the tenant'}
                <span className="block text-[11px] text-text-muted">{t('deviceViews.shareHint') || 'Every member sees it; the list stays limited to what each one may see.'}</span>
              </span>
            </label>
            <label className="flex items-center gap-2 text-sm text-text-primary">
              <input type="checkbox" checked={makeDefault} onChange={(e) => setMakeDefault(e.target.checked)} className="accent-accent" />
              {t('deviceViews.defaultOption') || 'Open the list on this view'}
            </label>
          </>
        )}
        <button type="submit" className="hidden" aria-hidden tabIndex={-1} />
      </form>
    </Modal>
  );
}
