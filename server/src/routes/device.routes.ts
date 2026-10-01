import { Router } from 'express';
import { deviceService } from '../services/device.service';
import { requireDeviceRead, requireDeviceWrite, requireTenantCapability } from '../middleware/rbac';
import { permissionService } from '../services/permission.service';
import { hasGlobalView, parseRequestDeviceId } from '../services/deviceScope.service';
import { asTargetTenant, globalViewRead, globalViewScope } from '../middleware/dbContext';
import { db } from '../db';
import { launchChromium } from '../utils/chromium';
import { logger } from '../utils/logger';

const router = Router();

// Tenant rule of these routes: the devices of the session's tenant. The
// master tenant's global view (every tenant) is a platform administrator's
// only (hasGlobalView), never a master-tenant member's, and it covers the
// reads and the device update (PATCH /:id); the state changes (approve,
// refuse, suspend, unsuspend, delete, bulk delete) stay on the session's
// tenant for everyone. A device out of reach answers like an unknown one
// (404).
//
// Database contexts (rls-tenant §6.3, §8.2): the reads that accept the
// global view run in the context 'platform' (globalViewScope); the device
// update from the global view reads the device there, then writes in the
// context of the device's tenant (asTargetTenant); everything else runs in
// the session tenant's context.

// ── Static / collection routes (must come before /:id routes) ─────────────────

// GET /api/devices
router.get('/', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const { groupId, includeSubgroups, status, approvalStatus, search, osType, osName, osVersion, page, pageSize, sortBy, sortOrder, ungrouped, staleHours, tags, tenantIds } = req.query as any;

    // Tags arrive either as repeated query params (`?tags=a&tags=b`)
    // → already an array — or as a comma-separated string. Normalise.
    let tagsArr: string[] | undefined;
    if (Array.isArray(tags)) tagsArr = tags.map(String).filter(Boolean);
    else if (typeof tags === 'string' && tags.length > 0) tagsArr = tags.split(',').map((t) => t.trim()).filter(Boolean);

    // Same parsing rules for `tenantIds` (global view only — the service
    // drops it for every other caller).
    let tenantIdsArr: number[] | undefined;
    if (Array.isArray(tenantIds)) tenantIdsArr = tenantIds.map((v) => parseInt(String(v))).filter(Number.isFinite);
    else if (typeof tenantIds === 'string' && tenantIds.length > 0) {
      tenantIdsArr = tenantIds.split(',').map((v: string) => parseInt(v.trim())).filter(Number.isFinite);
    }

    // osName / osVersion accept either a single value (legacy single-
    // select callers) or a comma-separated list / repeated param
    // (multi-select picker in DeviceTable). Service normalises both
    // shapes into a WHERE IN clause.
    const parseStringList = (raw: unknown): string[] | undefined => {
      if (Array.isArray(raw)) return raw.map(String).filter(Boolean);
      if (typeof raw === 'string' && raw.length > 0) return raw.split(',').map((s) => s.trim()).filter(Boolean);
      return undefined;
    };
    const osNames = parseStringList(osName);
    const osVersions = parseStringList(osVersion);

    const result = await deviceService.getDevices(req.tenantId!, {
      groupId: groupId ? parseInt(groupId) : undefined,
      includeSubgroups: includeSubgroups === 'true',
      status, approvalStatus, search, osType,
      osName: osNames,
      osVersion: osVersions,
      page: page ? parseInt(page) : undefined,
      pageSize: pageSize ? parseInt(pageSize) : undefined,
      sortBy, sortOrder,
      ungrouped: ungrouped === 'true' || ungrouped === true,
      staleHours: staleHours ? parseInt(staleHours) : undefined,
      tags: tagsArr,
      tenantIds: tenantIdsArr,
    }, { globalView: hasGlobalView(req) });

    // Filter by visible devices for non-admins. The visibility set
    // now includes pre-approval devices "claimed" via their API key's
    // default group + devices in the catch-all `ungrouped` scope —
    // see permissionService.getVisibleDeviceIds for the full ruleset.
    if (req.session.role !== 'admin') {
      const visible = await permissionService.getVisibleDeviceIds(req.session.userId!, false);
      if (Array.isArray(visible)) {
        const visibleSet = new Set(visible);
        result.items = result.items.filter((d: any) => visibleSet.has(d.id));
        result.total = result.items.length;
      }
    }

    res.json({ data: result });
  } catch (err) { next(err); }
});

// GET /api/devices/export
router.get('/export', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const { format, groupId, includeSubgroups, status, approvalStatus, search, osType, sortBy, sortOrder, ungrouped } = req.query as any;
    const fmt = (format ?? 'csv').toString().toLowerCase();
    if (!['csv', 'xlsx', 'pdf'].includes(fmt)) {
      return res.status(400).json({ error: 'Invalid format (csv|xlsx|pdf)' });
    }

    let devices = await deviceService.exportDevices(req.tenantId!, {
      groupId: groupId ? parseInt(groupId) : undefined,
      includeSubgroups: includeSubgroups === 'true',
      status, approvalStatus, search, osType, sortBy, sortOrder,
      ungrouped: ungrouped === 'true' || ungrouped === true,
    });

    // Non-admins: filter to visible devices only
    if (req.session.role !== 'admin') {
      const visible = await permissionService.getVisibleDeviceIds(req.session.userId!, false);
      if (Array.isArray(visible)) {
        const visibleSet = new Set(visible);
        devices = devices.filter((d: any) => visibleSet.has(d.id));
      }
    }

    const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
    const baseName = `obligarth-devices-${ts}`;

    // Rows for the export — stable column order. `pdf: false` keeps a column
    // out of the (width-constrained) PDF while still exporting it to CSV/XLSX,
    // so the spreadsheet holds every column and the PDF stays readable.
    const columns: Array<{ header: string; key: string; width: number; pdf?: boolean }> = [
      { header: 'Hostname',       key: 'hostname',      width: 24 },
      { header: 'Display Name',   key: 'displayName',   width: 24 },
      { header: 'Status',         key: 'status',        width: 12 },
      { header: 'OS',             key: 'osName',        width: 18 },
      { header: 'OS Version',     key: 'osVersion',     width: 16, pdf: false },
      { header: 'Architecture',   key: 'osArch',        width: 10, pdf: false },
      { header: 'Group',          key: 'groupName',     width: 20 },
      // ── Hardware summary ─────────────────────────────────────────────────
      { header: 'CPU Model',       key: 'cpuModel',     width: 30, pdf: false },
      { header: 'CPU Cores',       key: 'cpuCores',     width: 9 },
      { header: 'RAM Total (GB)',  key: 'ramTotalGb',   width: 12 },
      // ── Network / identity ────────────────────────────────────────────────
      { header: 'Local IP',       key: 'ipLocal',       width: 16 },
      { header: 'Public IP',      key: 'ipPublic',      width: 16, pdf: false },
      { header: 'MAC Address',    key: 'macAddress',    width: 18, pdf: false },
      { header: 'Last Seen',      key: 'lastSeenAt',    width: 22 },
      { header: 'Last User',      key: 'lastLoggedInUser', width: 18, pdf: false },
      { header: 'UUID',           key: 'uuid',          width: 38, pdf: false },
    ];

    // Blank (not 0) when a value is unknown.
    const r1 = (n: number) => (Number.isFinite(n) ? Math.round(n * 10) / 10 : '');

    const rows = devices.map((d: any) => ({
      hostname:         d.hostname ?? '',
      displayName:      d.displayName ?? '',
      status:           d.status ?? '',
      osName:           d.osName ?? d.osType ?? '',
      osVersion:        d.osVersion ?? '',
      osArch:           d.osArch ?? '',
      groupName:        d.groupName ?? '',
      cpuModel:         d.cpuModel ?? '',
      cpuCores:         d.cpuCores ?? '',
      ramTotalGb:       r1(Number(d.ramTotalGb ?? NaN)),
      ipLocal:          d.ipLocal ?? '',
      ipPublic:         d.ipPublic ?? '',
      macAddress:       d.macAddress ?? '',
      lastSeenAt:       d.lastSeenAt ?? '',
      lastLoggedInUser: d.lastLoggedInUser ?? '',
      uuid:             d.uuid ?? '',
    }));

    const ExcelJS = (await import('exceljs')).default;

    if (fmt === 'csv') {
      const wb = new ExcelJS.Workbook();
      const ws = wb.addWorksheet('Devices');
      ws.columns = columns;
      rows.forEach((r) => ws.addRow(r));
      const buffer = await wb.csv.writeBuffer();
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.csv"`);
      return res.send(Buffer.from(buffer as any));
    }

    if (fmt === 'xlsx') {
      const wb = new ExcelJS.Workbook();
      wb.creator = 'Obligarth';
      wb.created = new Date();
      const ws = wb.addWorksheet('Devices');
      ws.columns = columns;
      ws.getRow(1).font = { bold: true };
      ws.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F2937' } };
      ws.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
      rows.forEach((r) => ws.addRow(r));
      ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
      const buffer = await wb.xlsx.writeBuffer();
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.xlsx"`);
      return res.send(Buffer.from(buffer as any));
    }

    // PDF via playwright (renders an HTML table to PDF). Curated column subset
    // (drop `pdf: false`) so the page stays readable — the full inventory is in
    // the CSV/XLSX exports.
    const pdfColumns = columns.filter((c) => c.pdf !== false);
    const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
    const headHtml = pdfColumns.map((c) => `<th>${escapeHtml(c.header)}</th>`).join('');
    const rowsHtml = rows.map((r) =>
      `<tr>${pdfColumns.map((c) => `<td>${escapeHtml(String((r as any)[c.key] ?? ''))}</td>`).join('')}</tr>`
    ).join('');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Devices</title><style>
body { font-family: -apple-system, Segoe UI, sans-serif; font-size: 9px; color: #111; margin: 20px; }
h1 { font-size: 14px; margin: 0 0 12px; }
.meta { font-size: 8px; color: #666; margin-bottom: 12px; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; }
th { background: #1f2937; color: white; font-weight: 600; }
tr:nth-child(even) td { background: #f9fafb; }
</style></head><body>
<h1>Obligarth — Devices export</h1>
<div class="meta">${devices.length} devices · generated ${new Date().toISOString()}</div>
<table><thead><tr>${headHtml}</tr></thead><tbody>${rowsHtml}</tbody></table>
</body></html>`;

    const browser = await launchChromium();
    try {
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'domcontentloaded' });
      const pdf = await page.pdf({ format: 'A4', landscape: true, margin: { top: '15mm', bottom: '15mm', left: '10mm', right: '10mm' }, printBackground: true });
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.pdf"`);
      return res.send(pdf);
    } finally {
      await browser.close();
    }
  } catch (err) { next(err); }
});

// GET /api/devices/summary
router.get('/summary', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const summary = await deviceService.getFleetSummary(req.tenantId!, { globalView: hasGlobalView(req) });
    res.json({ data: summary });
  } catch (err) { next(err); }
});

// GET /api/devices/fleet-timeseries?days=14
// Returns daily online/offline/total/pendingUpdates/stale72/critical for the
// last N days. Used by the dashboard hero sparklines and the "Activité du
// parc" chart. The current-day point is always synthesized from live state
// (no waiting for the nightly snapshot job).
router.get('/fleet-timeseries', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const days = Math.min(parseInt(String(req.query.days ?? '14')) || 14, 90);
    const series = await deviceService.getFleetTimeseries(req.tenantId!, days, { globalView: hasGlobalView(req) });
    res.json({ data: series });
  } catch (err) { next(err); }
});

// GET /api/devices/fleet-hourly?hours=24
// Hourly granularity timeseries for the dashboard "Activité du parc" 24h
// view. Returns one point per hour (capped 7d), each with total / online /
// offline / pending_updates / stale_72h.
router.get('/fleet-hourly', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const hours = Math.min(168, Math.max(2, parseInt(String(req.query.hours ?? '24')) || 24));
    const series = await deviceService.getFleetHourlySeries(req.tenantId!, hours, { globalView: hasGlobalView(req) });
    res.json({ data: series });
  } catch (err) { next(err); }
});

// GET /api/devices/os-facets
// Grouped facets used by the /devices 3-tier OS filter (family → name → build).
// Returns one row per (osType, osName, osVersion) triplet with a count, so the
// client can render dropdowns showing only options that actually have devices.
router.get('/os-facets', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const facets = await deviceService.getOsFacets(req.tenantId!, { globalView: hasGlobalView(req) });
    res.json({ data: facets });
  } catch (err) { next(err); }
});

// GET /api/devices/tags
// Distinct tag list for the tenant with per-tag device counts. Drives the
// /devices tag-filter chip popover so admins pick from existing tags
// (typo-free) rather than retyping. Returns [{ tag, count }] desc by count.
router.get('/tags', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const tags = await deviceService.getTagFacets(req.tenantId!, { globalView: hasGlobalView(req) });
    res.json({ data: tags });
  } catch (err) { next(err); }
});

// GET /api/devices/group-stats — stats per group for dashboard
router.get('/group-stats', globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const tenantId = req.tenantId!;
    const isMaster = hasGlobalView(req);

    // Device counts per group + status. The global view sees the
    // aggregate across every tenant; every other caller stays scoped.
    const deviceQ = db('devices')
      .where({ approval_status: 'approved' })
      .whereNot({ status: 'pending_uninstall' })
      .select('group_id', 'status')
      .count('* as count')
      .groupBy('group_id', 'status');
    if (!isMaster) deviceQ.where({ tenant_id: tenantId });
    const deviceRows = await deviceQ;

    // Group metadata (parent + sortOrder feed the dashboard's hierarchical
    // "Vue par groupe" — root → children indented by depth, ordered by the
    // admin-defined sort_order rather than device count).
    // On master tenant we also pull `tenant_id` + tenant name so the
    // dashboard can bucket groups under their owning tenant (mirroring
    // the sidebar grouping). Without this, master shows a flat mix of
    // "Serveurs" / "Postes" / etc. from every tenant — unreadable.
    const groupsQ = db('device_groups as g')
      .leftJoin('tenants as t', 't.id', 'g.tenant_id')
      .select('g.id', 'g.name', 'g.parent_id', 'g.sort_order', 'g.tenant_id', 't.name as tenant_name');
    if (!isMaster) groupsQ.where({ 'g.tenant_id': tenantId });
    const groups = await groupsQ as Array<{
      id: number; name: string; parent_id: number | null; sort_order: number;
      tenant_id: number; tenant_name: string | null;
    }>;

    // Build stats map
    const statsMap = new Map<number | null, any>();

    const getOrCreate = (gid: number | null) => {
      if (!statsMap.has(gid)) {
        statsMap.set(gid, {
          groupId: gid, groupName: null, parentId: null, sortOrder: 0,
          tenantId: null, tenantName: null,
          online: 0, offline: 0, warning: 0, critical: 0, total: 0,
        });
      }
      return statsMap.get(gid)!;
    };

    for (const row of deviceRows) {
      const s = getOrCreate(Number(row.group_id));
      const count = parseInt(String(row.count));
      s.total += count;
      if (row.status === 'online') s.online += count;
      else if (row.status === 'offline') s.offline += count;
      else if (row.status === 'warning') s.warning += count;
      else if (row.status === 'update_error') s.warning += count;
      else if (row.status === 'critical') s.critical += count;
    }

    // Make sure every group has a stats row even if it has no devices —
    // the hierarchical render still wants the empty group to appear.
    for (const g of groups) getOrCreate(g.id);

    // Set group names + parent + sortOrder + tenant info
    const groupMap = new Map(groups.map((g) => [g.id, g]));
    for (const [gid, stats] of statsMap) {
      if (gid != null) {
        const g = groupMap.get(gid);
        stats.groupName = g?.name ?? 'Unknown';
        stats.parentId = g?.parent_id ?? null;
        stats.sortOrder = g?.sort_order ?? 0;
        stats.tenantId = g?.tenant_id ?? null;
        stats.tenantName = g?.tenant_name ?? null;
      }
    }

    // Pre-sort by (parentId nulls first, then sortOrder) so the client can
    // build the tree in linear order without a second pass.
    res.json({ data: Array.from(statsMap.values()).sort((a: any, b: any) => {
      if ((a.parentId ?? -1) !== (b.parentId ?? -1)) return (a.parentId ?? -1) - (b.parentId ?? -1);
      if (a.sortOrder !== b.sortOrder) return a.sortOrder - b.sortOrder;
      return (a.groupName ?? '').localeCompare(b.groupName ?? '');
    }) });
  } catch (err) { next(err); }
});

// POST /api/devices/bulk/approve
router.post('/bulk/approve', requireTenantCapability('agent_config:approval'), async (req, res, next) => {
  try {
    const { ids, deviceIds } = req.body;
    const list = ids ?? deviceIds ?? [];
    await deviceService.bulkApprove(list, req.tenantId!, req.session.userId!);
    res.json({ success: true, count: list.length });
  } catch (err) { next(err); }
});

// DELETE /api/devices/bulk/delete — body { ids } or { deviceIds }.
// The ids are narrowed to the devices of the session's tenant BEFORE
// anything else (no mass deletion across tenants, even for the global
// view): an id of another tenant reaches neither the restriction check nor
// the purge, and a request with none of the tenant's devices answers 404.
// Then the same gate as a single deletion: the `device.delete` restriction
// (step-up, or a two-person approval executed by deviceApproval.ts).
router.delete('/bulk/delete', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const { ids, deviceIds } = (req.body ?? {}) as { ids?: unknown; deviceIds?: unknown };
    const raw = ids ?? deviceIds;
    if (!Array.isArray(raw) || raw.length === 0) {
      return res.status(400).json({ error: 'deviceIds required' });
    }
    const requested = [...new Set(raw.map(parseRequestDeviceId).filter((n): n is number => n !== null))];
    const devices = requested.length
      ? await db('devices').whereIn('id', requested).andWhere({ tenant_id: req.tenantId! }).select('id') as Array<{ id: number }>
      : [];
    if (devices.length === 0) {
      return res.status(404).json({ error: 'No matching devices in this tenant' });
    }
    const validIds = devices.map((d) => Number(d.id));

    const { applyRestriction } = await import('../services/restriction.service');
    const { deviceList } = await import('../services/approvalDescribe');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'device.delete',
      deviceIds: validIds,
      approvalRequestType: 'batch_command',
      approvalDescription: `Delete ${await deviceList(req.tenantId!, validIds)}`,
      approvalPayload: { action: 'delete_devices', deviceIds: validIds },
    });
    if (!approved) return;

    const deleted = await deviceService.bulkDelete(validIds, req.tenantId!);
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.bulk_deleted', {
        resourceType: 'device',
        resourcePath: deleted.join(','),
        details: { count: deleted.length },
      });
    } catch {}
    res.json({ success: true, count: deleted.length });
  } catch (err) { next(err); }
});

// POST /api/devices/batch/change-group — move N devices to a new group in one shot.
// Body: { deviceIds: number[], groupId: number | null }
router.post('/batch/change-group', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const { deviceIds, groupId } = req.body as { deviceIds: number[]; groupId: number | null };
    if (!Array.isArray(deviceIds) || deviceIds.length === 0) {
      return res.status(400).json({ error: 'deviceIds required' });
    }
    // Validate group if provided (null = ungrouped).
    if (groupId !== null && groupId !== undefined) {
      const grp = await db('device_groups').where({ id: groupId, tenant_id: req.tenantId! }).first();
      if (!grp) return res.status(404).json({ error: 'Group not found' });
    }
    const normalized = groupId === undefined ? null : groupId;

    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'device.bulk_group_change',
      deviceIds,
      approvalRequestType: 'batch_command',
      approvalDescription: `Move to ${await (await import('../services/approvalDescribe')).groupLabel(req.tenantId!, normalized)} — ${await (await import('../services/approvalDescribe')).deviceList(req.tenantId!, deviceIds)}`,
      approvalPayload: { action: 'change_group', deviceIds, params: { groupId: normalized } },
    });
    if (!approved) return;

    // Capture previous groupIds so only the devices whose group changed count.
    const prev = await db('devices')
      .whereIn('id', deviceIds)
      .andWhere({ tenant_id: req.tenantId! })
      .select('id', 'group_id');
    const prevById = new Map(prev.map((p: any) => [p.id, p.group_id]));

    await db('devices')
      .whereIn('id', deviceIds)
      .andWhere({ tenant_id: req.tenantId! })
      .update({ group_id: normalized, updated_at: new Date() });

    let changedCount = 0;
    for (const id of deviceIds) {
      if (prevById.get(id) !== normalized) changedCount++;
    }

    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.bulk_group_changed', {
        resourceType: 'device',
        resourcePath: deviceIds.join(','),
        details: { count: deviceIds.length, changed: changedCount, toGroupId: normalized },
      });
    } catch {}

    res.json({ data: { updated: deviceIds.length, changed: changedCount } });
  } catch (err) { next(err); }
});

// ── Single-device routes (:id) ────────────────────────────────────────────────

// GET /api/devices/:id
router.get('/:id', requireDeviceRead(), globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const device = await deviceService.getDeviceById(parseInt(req.params.id), req.tenantId!, { globalView: hasGlobalView(req) });
    if (!device) return res.status(404).json({ error: 'Device not found' });
    res.json({ data: device });
  } catch (err) { next(err); }
});

// PATCH /api/devices/:id — a `groupId` must be a group of the device's own
// tenant (404 'Group not found' otherwise, as for an unknown group), and one
// the caller can write unless it is a platform administrator (403).
router.patch('/:id', requireDeviceWrite(), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    const view = { globalView: hasGlobalView(req) };
    // From the global view: the device is found across tenants (context
    // 'platform'), then written in its own tenant's context (one target per
    // request); otherwise in the session's tenant.
    let targetTenantId = req.tenantId!;
    if (view.globalView) {
      const found = Number.isSafeInteger(deviceId) && deviceId > 0
        ? await globalViewRead(req, () => db('devices').where({ id: deviceId }).first('tenant_id')) as { tenant_id: number } | undefined
        : undefined;
      if (!found) return res.status(404).json({ error: 'Device not found' });
      targetTenantId = Number(found.tenant_id);
    }
    const device = await asTargetTenant(req, targetTenantId, () => deviceService.updateDevice(deviceId, req.tenantId!, req.body ?? {}, view, {
      groupWriterId: req.session.role === 'admin' ? undefined : req.session.userId!,
    }));
    if (!device) return res.status(404).json({ error: 'Device not found' });
    // Filed in the device's tenant (from the global view: the client's log,
    // rls-tenant EX-08): the fields changed, never their values.
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReqAs(req, targetTenantId, 'device.updated', {
        deviceId, resourceType: 'device', resourcePath: String(deviceId),
        details: { fields: Object.keys((req.body ?? {}) as Record<string, unknown>).slice(0, 20).map((k) => k.slice(0, 64)) },
      });
    } catch {}
    res.json({ data: device });
  } catch (err) { next(err); }
});

// ── Change events (Blame Ribbon source) ─────────────────────────────────────
// Read-through union over the tables Obligarth already writes: what changed on
// this device in a window. Guarded like the device itself (requireDeviceRead) —
// a weaker guard would be a permission bypass, since this exposes per-device
// history.
//
// The service also filters per CALLER (a non-admin does not see another user's
// audit rows), so the session identity is passed through rather than assumed.
router.get('/:id/change-events', requireDeviceRead(), globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    // Same tenant rule as GET /:id; the service applies it to the rows too
    // (global view passed explicitly, never inferred from the tenant id).
    if (!(await deviceService.getDeviceById(deviceId, req.tenantId!, { globalView: hasGlobalView(req) }))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { changeEventService, changeEventsQuerySchema } = await import('../services/changeEvent.service');
    const parsed = changeEventsQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid query' });
    }
    res.json({
      data: await changeEventService.getTimeline(deviceId, req.tenantId!, {
        ...parsed.data,
        callerUserId: req.session.userId!,
        callerIsAdmin: req.session.role === 'admin',
        globalView: hasGlobalView(req),
      }),
    });
  } catch (err) { next(err); }
});

// GET /api/devices/:id/change-events/summary?from=&to= — counts per kind
router.get('/:id/change-events/summary', requireDeviceRead(), globalViewScope('console.devices'), async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    if (!(await deviceService.getDeviceById(deviceId, req.tenantId!, { globalView: hasGlobalView(req) }))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { changeEventService, changeEventsSummaryQuerySchema } = await import('../services/changeEvent.service');
    const parsed = changeEventsSummaryQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid query' });
    }
    res.json({
      data: await changeEventService.getSummary(deviceId, req.tenantId!, {
        ...parsed.data,
        callerUserId: req.session.userId!,
        callerIsAdmin: req.session.role === 'admin',
        globalView: hasGlobalView(req),
      }),
    });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/approve
router.post('/:id/approve', requireTenantCapability('agent_config:approval'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const device = await deviceService.approveDevice(id, req.tenantId!, req.session.userId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.approved', {
        deviceId: id, resourceType: 'device', resourcePath: String(id),
        details: { hostname: device.hostname },
      });
    } catch {}
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/refuse
router.post('/:id/refuse', requireTenantCapability('agent_config:approval'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const device = await deviceService.refuseDevice(id, req.tenantId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.refused', {
        deviceId: id, resourceType: 'device', resourcePath: String(id),
        details: { hostname: device.hostname },
      });
    } catch {}
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/suspend
router.post('/:id/suspend', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const device = await deviceService.suspendDevice(id, req.tenantId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.suspended', {
        deviceId: id, resourceType: 'device', resourcePath: String(id),
        details: { hostname: device.hostname },
      });
    } catch {}
    res.json({ data: device });
  } catch (err) { next(err); }
});

// POST /api/devices/:id/unsuspend
router.post('/:id/unsuspend', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const device = await deviceService.unsuspendDevice(id, req.tenantId!);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.unsuspended', {
        deviceId: id, resourceType: 'device', resourcePath: String(id),
        details: { hostname: device.hostname },
      });
    } catch {}
    res.json({ data: device });
  } catch (err) { next(err); }
});

// The transfer of a device to another tenant (POST /:id/transfer,
// /batch/transfer and their candidate lists) is gone (rls-tenant R10): a row
// never moves from one tenant to another. In an MDM a device changes client
// by a verified retirement, then a new enrollment.

// DELETE /api/devices/:id
router.delete('/:id', requireTenantCapability('devices.manage'), async (req, res, next) => {
  try {
    const id = parseRequestDeviceId(req.params.id);
    if (id === null) return res.status(404).json({ error: 'Device not found' });
    // The session's tenant only (no global view for a deletion).
    const existing = await deviceService.getDeviceById(id, req.tenantId!);
    if (!existing) return res.status(404).json({ error: 'Device not found' });

    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'device.delete',
      deviceIds: [id],
      approvalRequestType: 'device_uninstall',
      approvalDescription: `Delete device ${existing.displayName || existing.hostname || `#${id}`}`,
      approvalPayload: { deviceId: id, deleteOnly: true },
    });
    if (!approved) return;

    if (!(await deviceService.deleteDevice(id, req.tenantId!))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, 'device.deleted', {
        deviceId: id, resourceType: 'device', resourcePath: String(id),
        details: { hostname: existing?.hostname, displayName: existing?.displayName },
      });
    } catch {}
    res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
