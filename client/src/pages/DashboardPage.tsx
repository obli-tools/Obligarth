import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  RefreshCw, ArrowRight, Clock, FolderOpen, AlertTriangle, AlertCircle, FolderTree, Wifi, Building2, ShieldAlert, Smartphone,
} from 'lucide-react';
import { MASTER_TENANT_ID, SocketEvents } from '@obligarth/shared';
import type { DeviceGroupTreeNode, MdmFleetPoint, MdmFleetSummary } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { groupsApi } from '@/api/groups.api';
import { useTenantStore } from '@/store/tenantStore';
import { registerSocketListener } from '@/socket/socketListeners';
import { ownershipLabel, platformLabel } from '@/components/mdm/PlatformIcon';
import { useTranslation } from 'react-i18next';
import { anonymize } from '@/utils/anonymize';
import { PageContainer } from '@/components/common/PageContainer';
import { Tip } from '@/components/common/Tip';
import { useMediaQuery, MEDIA } from '@/hooks/useMediaQuery';

// ── Sparkline (filled area + line) ───────────────────────────────────────────
// `color` goes through the style attribute, where a theme token
// (rgb(var(--c-...))) always resolves, rather than through SVG presentation
// attributes, whose support of var() is not uniform.

function Sparkline({ data, color, height = 36 }: { data: number[]; color: string; height?: number }) {
  if (data.length < 2) return <div style={{ height }} />;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const w = 200;
  const h = height;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * (h - 4) - 2;
    return [x, y];
  });
  const linePath = pts.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L${w},${h} L0,${h} Z`;
  const id = `sg-${color.replace(/[^a-z0-9]/gi, '')}`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ width: '100%', height }} className="block">
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   style={{ stopColor: color, stopOpacity: 0.4 }} />
          <stop offset="100%" style={{ stopColor: color, stopOpacity: 0 }} />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#${id})`} />
      <path d={linePath} fill="none" style={{ stroke: color }} strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  );
}

// ── Hero KPI card (featured: with spark + axis) ──────────────────────────────

function HeroFeatured({ label, value, color, series, days }: {
  label: string; value: number; color: string;
  series: number[]; days: { short: string; value: number }[];
}) {
  return (
    // h-full + flex-col so this card stretches with its row siblings.
    // The "Appareils total" card carries the most content (sparkline +
    // 4-day grid) so it sets the row height; the simpler HeroCards now
    // grow to match instead of looking visibly shorter.
    <div className="h-full flex flex-col rounded-xl p-5 relative overflow-hidden bg-gradient-to-br from-accent/10 via-bg-secondary to-bg-secondary shadow-[0_0_0_1px_rgb(var(--c-accent)/0.18)_inset,_0_6px_28px_-10px_rgb(var(--c-accent)/0.25)]">
      <div className="text-[11px] font-mono uppercase tracking-[0.14em] text-text-muted mb-3">{label}</div>
      <div className={`font-display text-[48px] font-semibold leading-none ${color}`}>{value}</div>
      <div className="mt-3"><Sparkline data={series} color="rgb(var(--c-accent-as-text))" /></div>
      <div className="grid grid-cols-4 mt-2 gap-2">
        {days.map((d, i) => {
          const isLast = i === days.length - 1;
          return (
            <div key={i} className={`flex flex-col items-start ${isLast ? 'text-text-primary' : 'text-text-muted'}`}>
              <span className="text-[10px] font-mono uppercase tracking-wider">{d.short}</span>
              <span className={`text-[12px] font-mono ${isLast ? 'text-text-primary font-semibold' : 'text-text-secondary'}`}>{d.value}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function HeroCard({ label, value, color, delta, deltaText, barPct, barColor, subStats, subStatsHeader }: {
  label: string; value: number; color: string;
  /** Numeric delta sign for the icon: positive = ↑, negative = ↓, 0 = stable */
  delta?: number | null;
  deltaText?: string;
  barPct?: number;
  barColor?: string;
  /** Optional secondary breakdown rendered under the bar — used by the
   *  "En ligne" card to expose the warning / critical / updating /
   *  updateError counts so the total of "online + offline" matches the
   *  "Appareils total" headline even when some agents are in those
   *  intermediate states. Items are shown even at value 0 when
   *  `subStatsHeader` is set — the header makes the layout grid-like
   *  and a missing item under "Dont :" would feel like a bug. */
  subStats?: Array<{ label: string; value: number; color?: string }>;
  /** Optional label rendered above the subStats row (e.g. "Dont :"). */
  subStatsHeader?: string;
}) {
  const deltaIconClass = delta == null ? 'text-text-muted' :
                          delta === 0   ? 'text-text-muted' :
                          delta > 0     ? 'text-green-400' : 'text-accent';
  const deltaIcon = delta == null ? '—' : delta === 0 ? '—' : delta > 0 ? '↑' : '↓';
  return (
    // h-full + flex-col so the card matches the row height set by the
    // taller HeroFeatured sibling. Without this the simpler cards
    // appeared shorter and the row felt unbalanced.
    <div className="h-full flex flex-col rounded-xl p-5 relative overflow-hidden bg-bg-secondary shadow-[0_1px_0_0_rgba(255,255,255,0.03),_0_6px_24px_-8px_rgba(0,0,0,0.45)]">
      <div className="text-[11px] font-mono uppercase tracking-[0.14em] text-text-muted mb-3">{label}</div>
      <div className={`font-display text-[36px] font-semibold leading-none ${color}`}>{value}</div>
      {(delta != null || deltaText) && (
        <div className={`text-[12px] font-mono mt-3 ${deltaIconClass}`}>
          <span className="mr-1">{deltaIcon}</span>{deltaText}
        </div>
      )}
      {barPct != null && (
        <div className="mt-2 h-1 w-full bg-white/[0.04] rounded">
          <div className="h-full rounded" style={{ width: `${Math.min(100, Math.max(0, barPct))}%`, background: barColor ?? 'rgb(var(--c-accent))' }} />
        </div>
      )}
      {subStats && subStats.length > 0 && (
        <div className="mt-2">
          {subStatsHeader && (
            <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-text-muted/80 mb-1">
              {subStatsHeader}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] font-mono text-text-muted">
            {subStats.map((s) => (
              <span key={s.label} className="flex items-center gap-1">
                <span className={s.color ?? 'text-text-secondary'}>{s.value}</span>
                <span>{s.label}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Donut ────────────────────────────────────────────────────────────────────

interface DonutSlice { name: string; value: number; color: string; to?: string }

function OsDonut({ slices, total }: { slices: DonutSlice[]; total: number }) {
  let cumulative = 0;
  const arcs = slices.map((s) => {
    const len = total > 0 ? (s.value / total) * 100 : 0;
    const offset = -cumulative + 25;
    cumulative += len;
    return { ...s, len, offset };
  });
  return (
    <div className="flex items-center gap-5">
      <svg viewBox="0 0 42 42" className="w-28 h-28 shrink-0">
        <circle cx="21" cy="21" r="15.915" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="3.5" />
        {arcs.map((a) => (
          <circle key={a.name} cx="21" cy="21" r="15.915" fill="none"
            stroke={a.color} strokeWidth="3.5"
            strokeDasharray={`${a.len} ${100 - a.len}`}
            strokeDashoffset={a.offset}
            transform="rotate(-90 21 21)" />
        ))}
        <text x="21" y="20" textAnchor="middle" dominantBaseline="middle" fill="rgb(var(--c-text-primary))" fontSize="6.5" fontWeight="600">{total}</text>
        <text x="21" y="26" textAnchor="middle" dominantBaseline="middle" fill="rgb(var(--c-text-muted))" fontSize="2.6" fontFamily="JetBrains Mono">total</text>
      </svg>
      <div className="flex-1 flex flex-col gap-2">
        {slices.map((s) => {
          const pct = total > 0 ? Math.round((s.value / total) * 100) : 0;
          const Inner = (
            <>
              <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: s.color }} />
              <span className="text-text-primary font-medium flex-1">{s.name}</span>
              <span className="text-text-muted font-mono text-[11px]">{s.value} · {pct}%</span>
            </>
          );
          return s.to ? (
            <Link key={s.name} to={s.to}
              className="flex items-center gap-3 text-[13px] -mx-1.5 px-1.5 py-0.5 rounded hover:bg-bg-hover transition-colors">
              {Inner}
            </Link>
          ) : (
            <div key={s.name} className="flex items-center gap-3 text-[13px]">
              {Inner}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Activity chart (enrolled and without contact, multi-tab) ─────────────────

type ActivityRange = '24h' | '7j' | '14j' | '30j';

// Unified shape so the chart can render both daily and hourly snapshots
// without branching internally — the parent maps each input to this.
interface ActivityPoint { label: string; enrolled: number; stale: number; total: number }

function ActivityChart({ data }: { data: ActivityPoint[] }) {
  const { t } = useTranslation();
  // Desktop keeps the historic 800×240 viewBox stretched to the card width.
  // Below lg the viewBox follows the measured width with a fixed 200px
  // height, so the axis labels stay at a real 10px instead of shrinking
  // to ~4px on a phone (preserveAspectRatio="none" scaled them).
  const isDesktop = useMediaQuery(MEDIA.lg);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [measured, setMeasured] = useState(0);
  useEffect(() => {
    if (isDesktop) return;
    const el = wrapRef.current;
    if (!el) return;
    const update = () => setMeasured(Math.round(el.getBoundingClientRect().width));
    update();
    if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, [isDesktop, data.length]);
  if (data.length < 2) {
    return (
      <div className="h-[240px] flex items-center justify-center text-text-muted text-sm">
        {t('dashboard.notEnoughHistory', 'Not enough history — data after 24h')}
      </div>
    );
  }
  const maxOnline = Math.max(...data.map(d => d.enrolled), 1);
  const maxOffline = Math.max(...data.map(d => d.stale), 1);
  const yMax = Math.max(maxOnline, maxOffline);
  const narrow = !isDesktop && measured > 0;
  const w = narrow ? Math.max(measured, 240) : 800;
  const h = narrow ? 200 : 240;
  const pad = { l: 36, r: 12, t: 16, b: 28 };
  const cw = w - pad.l - pad.r;
  const ch = h - pad.t - pad.b;
  const xOf = (i: number) => pad.l + (i / (data.length - 1)) * cw;
  const yOf = (v: number) => pad.t + (1 - v / yMax) * ch;
  const onlinePath = data.map((d, i) => `${i === 0 ? 'M' : 'L'}${xOf(i).toFixed(1)},${yOf(d.enrolled).toFixed(1)}`).join(' ');
  const offlinePath = data.map((d, i) => `${i === 0 ? 'M' : 'L'}${xOf(i).toFixed(1)},${yOf(d.stale).toFixed(1)}`).join(' ');
  const onlineArea = `${onlinePath} L${xOf(data.length - 1)},${pad.t + ch} L${xOf(0)},${pad.t + ch} Z`;
  const ticks = [0, 0.5, 1].map(t => yMax * t);

  return (
    <div ref={wrapRef} className="w-full">
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full block" preserveAspectRatio="none" style={narrow ? { height: h } : undefined}>
      <defs>
        <linearGradient id="ag-online" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#1edd8a" stopOpacity="0.30" />
          <stop offset="100%" stopColor="#1edd8a" stopOpacity="0" />
        </linearGradient>
      </defs>
      {/* Grid lines */}
      {ticks.map((v, i) => (
        <g key={i}>
          <line x1={pad.l} x2={w - pad.r} y1={yOf(v)} y2={yOf(v)} stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
          <text x={pad.l - 6} y={yOf(v) + 3} fontSize="10" fontFamily="JetBrains Mono" fill="rgb(var(--c-text-muted))" textAnchor="end">{Math.round(v)}</text>
        </g>
      ))}
      <path d={onlineArea} fill="url(#ag-online)" />
      <path d={onlinePath}  fill="none" stroke="#1edd8a" strokeWidth="1.8" strokeLinejoin="round" />
      <path d={offlinePath} fill="none" stroke="rgb(var(--c-text-muted))" strokeWidth="1.4" strokeDasharray="4 3" strokeLinejoin="round" />
      {/* X axis labels (first / mid / last only) */}
      {[0, Math.floor(data.length / 2), data.length - 1].map(i => (
        <text key={i} x={xOf(i)} y={h - 8} fontSize="10" fontFamily="JetBrains Mono" fill="rgb(var(--c-text-muted))" textAnchor="middle">
          {data[i].label}
        </text>
      ))}
    </svg>
    </div>
  );
}

// ── Mini-stat compact card ───────────────────────────────────────────────────

function MiniStat({ icon, label, value, sub, color = 'text-text-primary', to }: {
  icon: React.ReactNode; label: string; value: React.ReactNode; sub?: string;
  color?: string; to?: string;
}) {
  const body = (
    <div className="flex items-center gap-3 rounded-lg bg-bg-secondary px-3.5 py-2.5 shadow-[0_1px_0_0_rgba(255,255,255,0.03),_0_4px_16px_-8px_rgba(0,0,0,0.35)]">
      <div className="w-8 h-8 rounded-md bg-bg-hover flex items-center justify-center shrink-0 text-text-muted">
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-text-muted truncate">{label}</div>
        <div className={`text-[14px] font-semibold leading-tight ${color} truncate`}>{value}</div>
        {sub && <div className="text-[10px] font-mono text-text-muted truncate">{sub}</div>}
      </div>
    </div>
  );
  return to ? <Link to={to} className="block hover:opacity-90 transition-opacity">{body}</Link> : body;
}

// ── Group view (recursive cards) ─────────────────────────────────────────────
// One card per group of the tree, with the MDM counters of its subtree (modele-donnees-mdm §11.3): devices under
// management, enrolled, non compliant, in configuration error, without contact.

function GroupCard({ group, children, depth = 0 }: { group: DeviceGroupTreeNode; children?: React.ReactNode; depth?: number }) {
  const { t } = useTranslation();
  const total = group.total ?? group.deviceCount ?? 0;
  const enrolled = group.enrolledCount ?? 0;
  const nonCompliant = group.nonCompliantCount ?? 0;
  const configErrors = group.configErrorCount ?? 0;
  const stale = group.staleCount ?? 0;
  const healthy = Math.max(0, enrolled - nonCompliant);
  const pct = total > 0 ? Math.round((healthy / total) * 100) : 0;
  const barColor = total === 0 ? 'rgba(255,255,255,0.10)' : nonCompliant > 0 ? '#f5a623' : '#1edd8a';
  const counters: Array<{ n: number; cls: string; icon: React.ReactNode; label: string; to: string }> = [
    { n: nonCompliant, cls: 'text-red-400', icon: <ShieldAlert size={13} />, label: t('groupPanel.nonCompliant') || 'Non compliant', to: `/devices?groupId=${group.id}&compliance=non_compliant` },
    { n: configErrors, cls: 'text-orange-400', icon: <AlertTriangle size={13} />, label: t('groupPanel.configErrors') || 'Configuration errors', to: `/devices?groupId=${group.id}&config=error` },
    { n: stale, cls: 'text-amber-400', icon: <Clock size={13} />, label: t('groupPanel.stale') || 'No contact', to: `/devices?groupId=${group.id}&contact=stale` },
  ];
  return (
    <div style={{ marginLeft: depth > 0 ? Math.min(depth, 4) * 14 : 0 }}>
      <div className="flex items-center gap-3 rounded-lg bg-bg-secondary px-3.5 py-2.5 max-md:flex-wrap">
        <Link to={`/devices?groupId=${group.id}`} className="flex min-w-0 flex-1 items-center gap-2 hover:text-accent transition-colors">
          <FolderOpen size={15} className="shrink-0 text-accent" />
          <span className="truncate text-[13px] font-medium text-text-primary">{anonymize(group.name)}</span>
        </Link>
        <Tip content={t('dashboard.tooltipEnrolled', { enrolled, total }) || `${enrolled} enrolled of ${total} under management`}>
          <span className="flex items-center gap-2 text-[12px] font-mono text-text-muted">
            <span className="text-green-400">{enrolled}</span>
            <span>/ {total}</span>
          </span>
        </Tip>
        <div className="h-1 w-24 shrink-0 rounded bg-white/[0.05] max-md:hidden" aria-hidden>
          <div className="h-full rounded" style={{ width: `${pct}%`, background: barColor }} />
        </div>
        <div className="flex shrink-0 items-center gap-2.5">
          {counters.filter((c) => c.n > 0).map((c) => (
            <Link key={c.label} to={c.to} title={`${c.label}: ${c.n}`} aria-label={`${c.label}: ${c.n}`}
              className={`flex items-center gap-1 text-[12px] font-mono ${c.cls} hover:opacity-80 coarse:min-h-9`}>
              {c.icon} {c.n}
            </Link>
          ))}
        </div>
      </div>
      {children && <div className="mt-1.5 space-y-1.5">{children}</div>}
    </div>
  );
}

function renderGroupNode(node: DeviceGroupTreeNode, depth: number): React.ReactNode {
  // A branch without any device under management is noise on the dashboard.
  if ((node.total ?? node.deviceCount ?? 0) === 0) return null;
  const children = [...node.children].sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name));
  return (
    <GroupCard key={node.id} group={node} depth={depth}>
      {children.some((c) => (c.total ?? c.deviceCount ?? 0) > 0) ? children.map((c) => renderGroupNode(c, depth + 1)) : undefined}
    </GroupCard>
  );
}

/** Master tenant (global view): the roots bucketed by tenant, the master first. */
function bucketGroupsByTenant(roots: DeviceGroupTreeNode[]): Array<{ tenantId: number; tenantName: string; roots: DeviceGroupTreeNode[] }> {
  const byTenant = new Map<number, { tenantId: number; tenantName: string; roots: DeviceGroupTreeNode[] }>();
  for (const r of roots) {
    if (!byTenant.has(r.tenantId)) byTenant.set(r.tenantId, { tenantId: r.tenantId, tenantName: r.tenantName ?? `Tenant ${r.tenantId}`, roots: [] });
    byTenant.get(r.tenantId)!.roots.push(r);
  }
  return [...byTenant.values()].sort((a, b) => {
    if (a.tenantId === MASTER_TENANT_ID) return -1;
    if (b.tenantId === MASTER_TENANT_ID) return 1;
    return a.tenantName.localeCompare(b.tenantName);
  });
}

// ── Dashboard ────────────────────────────────────────────────────────────────
// Fleet overview of the MDM (modele-donnees-mdm §11.3, conception §8.2): devices under management, enrolled,
// compliant, non compliant, being enrolled, without contact for mdmStaleAfterDays days; a ring by platform; the
// activity curve (enrolled, without contact); the groups with their counters.

const PLATFORM_COLORS: Record<string, string> = {
  ios: '#4f7bff', ipados: '#1edd8a', macos: '#f5a623', tvos: '#b07cff', visionos: '#ff6b9d', android: '#3ddc84',
};

const RANGE_HOURS: Record<ActivityRange, number | null> = { '24h': 24, '7j': null, '14j': null, '30j': null };
const RANGE_DAYS: Record<ActivityRange, number> = { '24h': 1, '7j': 7, '14j': 14, '30j': 30 };

export function DashboardPage() {
  const { t } = useTranslation();
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const isMaster = currentTenantId === MASTER_TENANT_ID;
  const [summary, setSummary] = useState<MdmFleetSummary | null>(null);
  const [tree, setTree] = useState<DeviceGroupTreeNode[]>([]);
  const [series, setSeries] = useState<MdmFleetPoint[]>([]);
  const [hourly, setHourly] = useState<MdmFleetPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [range, setRange] = useState<ActivityRange>('14j');

  const load = useCallback(async () => {
    try {
      const [s] = await Promise.all([
        mdmApi.fleetSummary(),
        groupsApi.tree().then(setTree).catch(() => setTree([])),
        mdmApi.fleetTimeseries(30).then(setSeries).catch(() => setSeries([])),
        mdmApi.fleetHourly(24).then(setHourly).catch(() => setHourly([])),
      ]);
      setSummary(s);
      setFailed(false);
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }, []);
  // Runs again after a tenant change; refreshed every minute and on a change of the registry.
  useEffect(() => {
    setLoading(true);
    void load();
    const timer = setInterval(() => { void load(); }, 60_000);
    return () => clearInterval(timer);
  }, [load, currentTenantId]);
  const reloadTimer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    const schedule = () => {
      if (reloadTimer.current) return;
      reloadTimer.current = setTimeout(() => { reloadTimer.current = undefined; void load(); }, 5000);
    };
    const offs = [SocketEvents.DEVICE_UPDATED, SocketEvents.DEVICE_DELETED, SocketEvents.DEVICE_CONFIG_CHANGED]
      .map((ev) => registerSocketListener(ev, schedule));
    return () => { offs.forEach((off) => off()); clearTimeout(reloadTimer.current); reloadTimer.current = undefined; };
  }, [load]);

  const total = summary?.total ?? 0;
  const enrolled = summary?.enrolled ?? 0;
  const enrolling = (summary?.enrolling ?? 0) + (summary?.awaitingConfiguration ?? 0);
  const pctOf = (n: number): number => (total > 0 ? Math.round((n / total) * 100) : 0);
  const deltas = summary?.deltas;
  const deltaText = (d: number | null | undefined, fallback: string): string => (d == null ? fallback
    : d === 0 ? (t('dashboard.stableVsYesterday', 'stable vs yesterday'))
      : `${d > 0 ? '+' : '−'}${Math.abs(d)} ${t('dashboard.vsYesterday', 'vs yesterday')}`);

  const activity: ActivityPoint[] = useMemo(() => {
    if (RANGE_HOURS[range]) {
      return hourly.map((p) => ({ label: `${new Date(p.at).getHours()}h`, enrolled: p.enrolled, stale: p.stale, total: p.total }));
    }
    return series.slice(-RANGE_DAYS[range]).map((p) => {
      const d = new Date(p.at);
      return { label: `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}`, enrolled: p.enrolled, stale: p.stale, total: p.total };
    });
  }, [range, series, hourly]);
  const sparkTotals = useMemo(() => series.slice(-14).map((p) => p.total), [series]);
  const lastDays = useMemo(() => series.slice(-4).map((p) => {
    const d = new Date(p.at);
    return { short: `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}`, value: p.total };
  }), [series]);

  const platformSlices: DonutSlice[] = useMemo(() => Object.entries(summary?.byPlatform ?? {})
    .filter(([, n]) => (n ?? 0) > 0)
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
    .map(([platform, n]) => ({ name: platformLabel(platform), value: n ?? 0, color: PLATFORM_COLORS[platform] ?? 'rgba(255,255,255,0.20)', to: `/devices?platform=${platform}` })),
  [summary]);
  const ownershipRows = useMemo(() => (['corporate', 'corporate_personal', 'personal'] as const)
    .map((o) => ({ key: o, n: summary?.byOwnership?.[o] ?? 0 })).filter((r) => r.n > 0), [summary]);

  const roots = useMemo(() => [...tree].sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name)), [tree]);
  const buckets = useMemo(() => (isMaster ? bucketGroupsByTenant(roots) : null), [isMaster, roots]);
  const groupedTotal = roots.reduce((n, r) => n + (r.total ?? r.deviceCount ?? 0), 0);
  const staleDays = summary?.staleAfterDays ?? 7;

  if (loading && !summary) {
    return <div className="flex h-64 items-center justify-center"><RefreshCw className="w-6 h-6 animate-spin text-text-muted" /></div>;
  }

  return (
    <PageContainer className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-bold text-text-primary">{t('dashboard.title')}</h1>
        <button type="button" onClick={() => { void load(); }} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
        <Link to="/devices" className="ml-auto inline-flex items-center gap-1 text-[12px] font-mono text-accent hover:opacity-80 coarse:py-2">
          {t('dashboard.allDevices', 'All devices')} <ArrowRight size={12} />
        </Link>
      </div>
      {failed && <p className="text-sm text-red-400">{t('common.error')}</p>}

      {/* KPI */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Link to="/devices?state=managed" className="h-full block hover:opacity-95 transition-opacity xl:col-span-1">
          <HeroFeatured label={t('dashboard.devicesManaged', 'devices managed')} value={total} color="text-text-primary" series={sparkTotals} days={lastDays} />
        </Link>
        <Link to="/devices?state=enrolled" className="h-full block hover:opacity-95 transition-opacity">
          <HeroCard
            label={t('dashboard.enrolled') || 'Enrolled'}
            value={enrolled}
            color="text-green-400"
            delta={deltas?.enrolledVsYesterday ?? null}
            deltaText={deltaText(deltas?.enrolledVsYesterday, `${pctOf(enrolled)}% ${t('dashboard.ofFleet', 'of fleet')}`)}
            barPct={pctOf(enrolled)}
            barColor="#1edd8a"
            subStatsHeader={t('dashboard.ofWhichHeader', 'Of which:')}
            subStats={[
              { label: t('dashboard.subStatEnrolling') || 'being enrolled', value: enrolling, color: 'text-blue-400' },
              { label: t('dashboard.subStatUnenrolling') || 'leaving', value: summary?.unenrolling ?? 0, color: 'text-amber-400' },
            ]}
          />
        </Link>
        <Link to="/devices?state=managed&compliance=compliant" className="h-full block hover:opacity-95 transition-opacity">
          <HeroCard
            label={t('dashboard.compliant') || 'Compliant'}
            value={summary?.compliant ?? 0}
            color="text-green-400"
            deltaText={`${pctOf(summary?.compliant ?? 0)}% ${t('dashboard.ofFleet', 'of fleet')}`}
            barPct={pctOf(summary?.compliant ?? 0)}
            barColor="#1edd8a"
            subStatsHeader={t('dashboard.ofWhichHeader', 'Of which:')}
            subStats={[{ label: t('dashboard.subStatUnknown') || 'not evaluated yet', value: summary?.complianceUnknown ?? 0 }]}
          />
        </Link>
        <Link to="/devices?state=managed&compliance=non_compliant" className="h-full block hover:opacity-95 transition-opacity">
          <HeroCard
            label={t('dashboard.nonCompliant') || 'Non compliant'}
            value={summary?.nonCompliant ?? 0}
            color={(summary?.nonCompliant ?? 0) > 0 ? 'text-red-400' : 'text-text-primary'}
            delta={deltas?.nonCompliantVsYesterday == null ? null : -deltas.nonCompliantVsYesterday}
            deltaText={deltaText(deltas?.nonCompliantVsYesterday, `${pctOf(summary?.nonCompliant ?? 0)}% ${t('dashboard.ofFleet', 'of fleet')}`)}
            barPct={pctOf(summary?.nonCompliant ?? 0)}
            barColor="#ff5d6c"
          />
        </Link>
        <Link to="/devices?state=managed&contact=stale" className="h-full block hover:opacity-95 transition-opacity">
          <HeroCard
            label={t('dashboard.staleDays', { count: staleDays }) || `No contact for ${staleDays} days`}
            value={summary?.stale ?? 0}
            color={(summary?.stale ?? 0) > 0 ? 'text-amber-400' : 'text-text-primary'}
            delta={deltas?.staleVsYesterday == null ? null : -deltas.staleVsYesterday}
            deltaText={deltaText(deltas?.staleVsYesterday, (summary?.stale ?? 0) === 0 ? (t('dashboard.allInContact') || 'whole fleet in contact') : `${pctOf(summary?.stale ?? 0)}% ${t('dashboard.ofFleet', 'of fleet')}`)}
            barPct={pctOf(summary?.stale ?? 0)}
            barColor="#f5a623"
          />
        </Link>
      </div>

      {/* Secondary counters */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <MiniStat icon={<Smartphone size={15} />} label={t('dashboard.enrolling') || 'Being enrolled'} value={enrolling} to="/devices?state=enrolling"
          sub={(summary?.awaitingConfiguration ?? 0) > 0 ? (t('dashboard.awaitingConfiguration', { count: summary?.awaitingConfiguration ?? 0 }) || `${summary?.awaitingConfiguration} in the setup assistant`) : undefined} />
        <MiniStat icon={<AlertTriangle size={15} />} label={t('dashboard.configErrors') || 'Configuration errors'} value={summary?.configErrors ?? 0}
          color={(summary?.configErrors ?? 0) > 0 ? 'text-orange-400' : 'text-text-primary'} to="/devices?state=managed&config=error"
          sub={(summary?.configPending ?? 0) > 0 ? (t('dashboard.configPending', { count: summary?.configPending ?? 0 }) || `${summary?.configPending} pending`) : undefined} />
        <MiniStat icon={<AlertCircle size={15} />} label={t('dashboard.lostMode') || 'Lost mode'} value={summary?.lostMode ?? 0}
          color={(summary?.lostMode ?? 0) > 0 ? 'text-red-400' : 'text-text-primary'} />
        <MiniStat icon={<Wifi size={15} />} label={t('dashboard.recentContact') || 'In contact within 24 h'} value={summary?.contact?.recent ?? 0}
          to="/devices?state=managed&contact=recent" sub={(summary?.contact?.never ?? 0) > 0 ? (t('dashboard.neverSeen', { count: summary?.contact?.never ?? 0 }) || `${summary?.contact?.never} never seen`) : undefined} />
      </div>

      {/* Activity + platforms */}
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2 rounded-xl bg-bg-secondary p-5">
          <div className="flex flex-wrap items-center gap-3 mb-3">
            <div className="text-[13px] font-semibold text-text-primary">{t('dashboard.fleetActivity', 'Fleet activity')}</div>
            <div className="flex items-center gap-3 text-[11px] font-mono text-text-muted">
              <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-green-400" /> {t('dashboard.enrolled') || 'Enrolled'}</span>
              <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 border-t border-dashed border-text-muted" /> {t('dashboard.staleShort') || 'No contact'}</span>
            </div>
            <div className="ml-auto flex gap-1">
              {(['24h', '7j', '14j', '30j'] as ActivityRange[]).map((r) => (
                <button key={r} type="button" onClick={() => setRange(r)}
                  className={`px-2 py-1 text-[11px] font-mono rounded coarse:min-h-9 coarse:px-3 ${range === r ? 'bg-accent/15 text-accent' : 'text-text-muted hover:text-text-primary'}`}>
                  {t(`dashboard.range.${r}`) || r}
                </button>
              ))}
            </div>
          </div>
          <ActivityChart data={activity} />
        </div>

        <div className="rounded-xl bg-bg-secondary p-5 space-y-5">
          <div>
            <div className="text-[13px] font-semibold text-text-primary mb-3">{t('dashboard.byPlatform') || 'Platforms'}</div>
            {platformSlices.length === 0
              ? <p className="text-sm text-text-muted">{t('dashboard.noData', 'No data')}</p>
              : <OsDonut slices={platformSlices} total={total} />}
          </div>
          {ownershipRows.length > 0 && (
            <div>
              <div className="text-[13px] font-semibold text-text-primary mb-2">{t('dashboard.byOwnership') || 'Ownership'}</div>
              <div className="space-y-1.5">
                {ownershipRows.map((r) => (
                  <Link key={r.key} to={`/devices?ownership=${r.key}`} className="flex items-center gap-3 text-[13px] -mx-1.5 px-1.5 py-0.5 rounded hover:bg-bg-hover transition-colors">
                    <span className="flex-1 text-text-primary">{ownershipLabel(t, r.key)}</span>
                    <span className="font-mono text-[11px] text-text-muted">{r.n} · {pctOf(r.n)}%</span>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Groups */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <FolderTree size={16} className="text-text-muted" />
          <div className="text-[13px] font-semibold text-text-primary">{t('dashboard.groupView', 'Group view')}</div>
          <span className="text-[11px] font-mono text-text-muted">{t('dashboard.groupViewCounters') || 'enrolled · non compliant · configuration errors · no contact'}</span>
          <Link to="/devices" className="ml-auto text-[12px] font-mono text-accent hover:opacity-80 transition-opacity coarse:py-2">
            {t('dashboard.manageGroups', 'Manage groups')}
          </Link>
        </div>
        {groupedTotal === 0 ? (
          <p className="rounded-lg bg-bg-secondary px-4 py-6 text-center text-sm text-text-muted">
            {roots.length === 0 ? t('dashboard.noGroups', 'No groups configured yet') : (t('dashboard.noGroupedDevice') || 'No device under management in a group yet')}
          </p>
        ) : buckets ? (
          buckets.map((b) => {
            const nodes = b.roots.map((r) => renderGroupNode(r, 0)).filter(Boolean);
            if (nodes.length === 0) return null;
            return (
              <div key={b.tenantId} className="space-y-1.5">
                <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-accent">
                  <Building2 size={12} /> {b.tenantName}
                </div>
                {nodes}
              </div>
            );
          })
        ) : (
          <div className="space-y-1.5">{roots.map((r) => renderGroupNode(r, 0))}</div>
        )}
        {total - groupedTotal > 0 && (
          <Link to="/devices?groupId=-1" className="flex items-center gap-2 rounded-lg bg-bg-secondary px-3.5 py-2.5 text-[13px] text-text-secondary hover:text-text-primary">
            <FolderOpen size={15} className="text-text-muted" />
            <span className="flex-1">{t('dashboard.ungrouped', 'Ungrouped')}</span>
            <span className="font-mono text-[12px] text-text-muted">{total - groupedTotal}</span>
          </Link>
        )}
      </div>
    </PageContainer>
  );
}
