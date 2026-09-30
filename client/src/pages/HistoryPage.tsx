import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
 History, RefreshCw, Monitor, Search, Loader2, X,
} from 'lucide-react';
import { clsx } from 'clsx';
import { commandApi } from '@/api/command.api';
import { useDeviceStore } from '@/store/deviceStore';
import { getSocket } from '@/socket/socketClient';
import type { Command } from '@obliance/shared';
import { anonymize } from '@/utils/anonymize';
import { TableScroll } from '@/components/common/TableScroll';
import toast from 'react-hot-toast';

// ─── Event model ─────────────────────────────────────────────────────────────

interface HistoryEvent {
 id: string;
 date: string;
 deviceId: number;
 label: string;
 /** i18n key of `label` (command types); `label` is the fallback. */
 labelKey?: string;
 status: string;
 duration?: number;
 createdByName?: string | null;
}

// ─── Converters ──────────────────────────────────────────────────────────────

// English fallbacks of history.cmd.<type>.
const CMD_LABELS: Record<string, string> = {
 run_script: 'Run Script',
 install_update: 'Install Update',
 scan_inventory: 'Scan Inventory',
 scan_updates: 'Scan Updates',
 check_compliance: 'Check Compliance',
 open_remote_tunnel: 'Open Tunnel',
 close_remote_tunnel: 'Close Tunnel',
 reboot: 'Reboot',
 shutdown: 'Shutdown',
 restart_agent: 'Restart Agent',
 list_services: 'List Services',
 restart_service: 'Restart Service',
 install_software: 'Install Software',
 uninstall_software: 'Uninstall Software',
};

function cmdToEvent(c: Command): HistoryEvent {
 return {
 id: `task:${c.id}`,
 date: c.createdAt,
 deviceId: c.deviceId,
 label: CMD_LABELS[c.type] ?? c.type,
 labelKey: CMD_LABELS[c.type] ? `history.cmd.${c.type}` : undefined,
 status: c.status,
 duration: c.durationMs ?? (c.result as any)?.duration,
 createdByName: c.createdByName,
 };
}

// ─── Status config ───────────────────────────────────────────────────────────

// `label` = English fallback of history.status.<status> (command statuses).
const STATUS_CFG: Record<string, { color: string; bg: string; label: string }> = {
 pending: { color: 'text-yellow-400', bg: 'bg-yellow-400/10', label: 'Pending' },
 sent: { color: 'text-blue-300', bg: 'bg-blue-300/10', label: 'Sent' },
 ack_running: { color: 'text-blue-400', bg: 'bg-blue-400/10', label: 'Running' },
 success: { color: 'text-green-400', bg: 'bg-green-400/10', label: 'Success' },
 failure: { color: 'text-red-400', bg: 'bg-red-400/10', label: 'Failed' },
 timeout: { color: 'text-orange-400', bg: 'bg-orange-400/10', label: 'Timeout' },
 cancelled: { color: 'text-gray-400', bg: 'bg-gray-400/10', label: 'Cancelled' },
};

const PAGE_SIZE = 50;

const TH = 'px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider';

// ─── Page ─────────────────────────────────────────────────────────────────────

export function HistoryPage({ embedded }: { embedded?: boolean } = {}) {
 const { t } = useTranslation();
 const socket = getSocket();
 const { getDevice, fetchDevices } = useDeviceStore();

 const [events, setEvents] = useState<HistoryEvent[]>([]);
 const [isLoading, setIsLoading] = useState(true);
 const [search, setSearch] = useState('');
 const [shown, setShown] = useState(PAGE_SIZE);

 const load = useCallback(async () => {
 setIsLoading(true);
 try {
 const cmdRes = await commandApi.list();
 setEvents(
 cmdRes.items.map(cmdToEvent)
 .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()),
 );
 } catch {
 toast.error(t('history.loadFailed', 'Failed to load history'));
 } finally {
 setIsLoading(false);
 }
 }, [t]);

 useEffect(() => {
 fetchDevices();
 load();
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, []);

 // Real-time: update task rows live
 useEffect(() => {
 const onCmd = (cmd: Command) => {
 setEvents(prev => {
 const id = `task:${cmd.id}`;
 const updated = cmdToEvent(cmd);
 const idx = prev.findIndex(e => e.id === id);
 if (idx >= 0) {
 const next = [...prev];
 next[idx] = updated;
 return next;
 }
 return [updated, ...prev].sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
 });
 };
 if (!socket) return;
 socket.on('COMMAND_UPDATED', onCmd);
 return () => {
 socket.off('COMMAND_UPDATED', onCmd);
 };
 }, [socket]);

 const deviceName = (id: number) => {
 const d = getDevice(id);
 return anonymize(d?.displayName || d?.hostname) || `#${id}`;
 };

 const eventLabel = (e: HistoryEvent) => (e.labelKey ? t(e.labelKey, e.label) : e.label);

 // Apply the search
 const filtered = events.filter(e => {
 if (search) {
 const q = search.toLowerCase();
 if (
 !e.label.toLowerCase().includes(q) &&
 !eventLabel(e).toLowerCase().includes(q) &&
 !deviceName(e.deviceId).toLowerCase().includes(q)
 ) return false;
 }
 return true;
 });

 const visible = filtered.slice(0, shown);
 const hasMore = filtered.length > shown;

 const statusLabel = (status: string) => {
 const cfg = STATUS_CFG[status];
 return cfg ? t(`history.status.${status}`, cfg.label) : status;
 };
 const formatMs = (ms: number) => (ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`);

 const deviceLink = (deviceId: number) => {
 const device = getDevice(deviceId);
 return device ? (
 <Link
 to={`/devices/${deviceId}`}
 className="group inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-accent transition-colors min-w-0"
 >
 <Monitor className="w-3.5 h-3.5 text-text-muted shrink-0 group-hover:text-accent" />
 <span className="truncate max-w-[140px]">{anonymize(device.displayName || device.hostname)}</span>
 </Link>
 ) : (
 <span className="text-xs text-text-muted">#{deviceId}</span>
 );
 };

 return (
 <div className={embedded ? 'flex flex-col min-h-0 space-y-5' : 'flex flex-col h-full min-h-0 p-3 sm:p-4 lg:p-6 space-y-5'}>

 {/* Header */}
 <div className="flex items-center justify-between gap-4 flex-wrap">
 {!embedded && <div className="flex items-center gap-3">
 <History className="w-5 h-5 text-text-muted" />
 <h1 className="text-xl font-semibold text-text-primary">{t('history.title', 'History')}</h1>
 {!isLoading && (
 <span className="text-xs text-text-muted bg-bg-secondary border border-transparent px-2 py-0.5 rounded-full">
 {t('history.eventCount', '{{count}} events', { count: filtered.length })}
 </span>
 )}
 </div>}
 <button
 onClick={() => { setShown(PAGE_SIZE); load(); }}
 disabled={isLoading}
 className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-bg-secondary border border-transparent text-sm text-text-muted hover:text-text-primary transition-colors disabled:opacity-50 coarse:min-h-10"
 >
 <RefreshCw className={clsx('w-4 h-4', isLoading && 'animate-spin')} />
 {t('common.refresh', 'Refresh')}
 </button>
 </div>

 {/* Toolbar: search */}
 <div className="flex items-center gap-3 flex-wrap">
 <div className="relative flex-1 min-w-[180px] max-w-xs ml-auto max-sm:max-w-none max-sm:basis-full">
 <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted pointer-events-none" />
 <input
 value={search}
 onChange={e => { setSearch(e.target.value); setShown(PAGE_SIZE); }}
 placeholder={t('history.searchPlaceholder', 'Search task, device…')}
 aria-label={t('history.searchPlaceholder', 'Search task, device…')}
 autoCapitalize="off"
 autoCorrect="off"
 spellCheck={false}
 className="w-full pl-8 pr-8 py-1.5 bg-bg-secondary rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent coarse:pr-11"
 />
 {search && (
 <button
 onClick={() => setSearch('')}
 aria-label={t('history.clearSearch', 'Clear search')}
 className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary transition-colors coarse:right-0 coarse:min-h-10 coarse:min-w-10 coarse:flex coarse:items-center coarse:justify-center"
 >
 <X className="w-3.5 h-3.5" />
 </button>
 )}
 </div>
 </div>

 {/* Content */}
 {isLoading ? (
 <div className="flex items-center justify-center flex-1 min-h-[240px]">
 <Loader2 className="w-6 h-6 animate-spin text-text-muted" />
 </div>
 ) : filtered.length === 0 ? (
 <div className="flex flex-col items-center justify-center flex-1 min-h-[240px] text-text-muted">
 <History className="w-10 h-10 mb-3 opacity-30" />
 <p className="text-sm">
 {search ? t('history.noResults', 'No results for this filter') : t('history.empty', 'No history yet')}
 </p>
 </div>
 ) : (
 <div className="flex-1 min-h-0 space-y-3">
 {/* Below md: Date / Device move under the action (stacked row), so
 Action and Status keep the width. */}
 <TableScroll className="bg-bg-secondary rounded-xl">
 <table className="w-full">
 <thead>
 <tr className="">
 <th className={clsx(TH, 'whitespace-nowrap hidden md:table-cell')}>{t('history.col.date', 'Date')}</th>
 <th className={clsx(TH, 'max-md:px-3')}>{t('history.col.action', 'Action')}</th>
 <th className={clsx(TH, 'hidden md:table-cell')}>{t('history.col.device', 'Device')}</th>
 <th className={clsx(TH, 'max-md:px-3')}>{t('history.col.status', 'Status')}</th>
 <th className={clsx(TH, 'hidden md:table-cell')}>{t('history.col.user', 'User')}</th>
 <th className={clsx(TH, 'hidden lg:table-cell')}>{t('history.col.duration', 'Duration')}</th>
 </tr>
 </thead>
 <tbody className="divide-y divide-border">
 {visible.map(ev => {
 const sc = STATUS_CFG[ev.status] ?? { color: 'text-text-muted', bg: 'bg-bg-tertiary', label: ev.status };
 const isLive = ev.status === 'ack_running';

 return (
 <tr key={ev.id} className="hover:bg-bg-tertiary transition-colors">

 {/* Date */}
 <td className="px-4 py-2.5 text-xs text-text-muted whitespace-nowrap hidden md:table-cell">
 {new Date(ev.date).toLocaleString()}
 </td>

 {/* Label (+ device · date · user on phones) */}
 <td className="px-4 py-2.5 max-w-0 max-md:px-3">
 <span className="text-sm text-text-primary font-medium truncate block">
 {eventLabel(ev)}
 </span>
 <div className="md:hidden mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-text-muted">
 {deviceLink(ev.deviceId)}
 <span className="whitespace-nowrap">{new Date(ev.date).toLocaleString()}</span>
 {ev.createdByName && <span className="truncate">{anonymize(ev.createdByName)}</span>}
 {ev.duration != null && <span className="whitespace-nowrap">{formatMs(ev.duration)}</span>}
 </div>
 {/* md–lg: the Duration column is hidden, show it here. */}
 {ev.duration != null && (
 <div className="hidden md:block lg:hidden mt-0.5 text-xs text-text-muted">
 {t('history.col.duration', 'Duration')}: {formatMs(ev.duration)}
 </div>
 )}
 </td>

 {/* Device link */}
 <td className="px-4 py-2.5 hidden md:table-cell whitespace-nowrap">
 {deviceLink(ev.deviceId)}
 </td>

 {/* Status badge */}
 <td className="px-4 py-2.5 max-md:px-3 max-md:align-top">
 <span className={clsx('inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium whitespace-nowrap', sc.color, sc.bg)}>
 {isLive && <Loader2 className="w-3 h-3 animate-spin" />}
 {statusLabel(ev.status)}
 </span>
 </td>

 {/* User */}
 <td className="px-4 py-2.5 text-xs text-text-muted hidden md:table-cell whitespace-nowrap">
 {anonymize(ev.createdByName) || '—'}
 </td>

 {/* Duration */}
 <td className="px-4 py-2.5 text-xs text-text-muted hidden lg:table-cell whitespace-nowrap">
 {ev.duration != null ? formatMs(ev.duration) : '—'}
 </td>
 </tr>
 );
 })}
 </tbody>
 </table>
 </TableScroll>

 {/* Pagination footer */}
 <div className="flex items-center justify-between gap-3 text-xs text-text-muted px-1">
 <span>{t('history.showingOf', 'Showing {{shown}} of {{total}}', { shown: Math.min(shown, filtered.length), total: filtered.length })}</span>
 {hasMore && (
 <button
 onClick={() => setShown(s => s + PAGE_SIZE)}
 className="px-3 py-1.5 rounded-lg bg-bg-secondary border border-transparent hover:text-text-primary transition-colors coarse:min-h-10"
 >
 {t('history.loadMore', 'Load {{count}} more', { count: Math.min(PAGE_SIZE, filtered.length - shown) })}
 </button>
 )}
 </div>
 </div>
 )}
 </div>
 );
}
