import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  NOTICE_ACK_CHANNELS, NOTICE_LOCALES, NOTICE_PLATFORMS, NOTICE_SETTINGS_FIELDS, NOTICE_SETTINGS_KEYS, OWNERSHIPS, noticeCompleteness,
  noticeDisplayed, noticeSettingsErrors, normalizeNoticeSetting,
  type NoticeAckChannel, type NoticeAcknowledgementCountDto, type NoticeContentDto, type NoticeLocale, type NoticePlatform,
  type NoticePreviewDto, type NoticeSettings, type NoticeSettingsDto, type NoticeSettingsKey, type NoticeVersionDto, type NoticesDto,
  type Ownership,
} from '@obligarth/shared';
import type { Knex } from 'knex';
import { audit } from '../../audit';
import { config } from '../../config';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { requireAnyTenantCapability, requireTenantCapability } from '../../middleware/rbac';
import { instanceStage } from '../../ops/stage';
import { permissionService } from '../../services/permission.service';
import { publicNoticeServed } from './surface';
import { generateNoticeNow, noticeSettingsOf } from './provider';
import { requestNoticeRegeneration } from './regenerate';

// =============================================================================
// Console API of the notice of the employees (P0-13 T6, USR-01), mounted with the privacy routes at /api/privacy
// (privacy/routes.ts), behind the session and the tenant:
//   GET  /notice-settings                       the settings of the tenant, their version, what a complete notice still
//                                               lacks (D7), the stage (D8) and whether an enrollment is refused for it,
//                                               the link of the public page (D6)
//   PUT  /notice-settings                       { settings, baseVersion? }: the settings given replace theirs (null
//                                               clears one), the others stay; plain text only (the CHECKs of the
//                                               table say the same). No double validation (D3): the capability, an
//                                               audit entry privacy.notice_settings_changed (standard: the keys
//                                               changed, never their values) and the regeneration of the notices
//                                               (privacy.notice-regenerate), both in the transaction of the change
//   GET  /notices                               the current versions with their text (the combinations shown at an
//                                               enrollment flagged: D13), the versions of the tenant (latest first,
//                                               optional filters platform, ownership, locale), their acknowledgements
//   GET  /notices/preview                       ?platform&ownership&locale: the notice the inputs in force give now,
//                                               nothing published (a tenant whose notices were never generated yet)
//   GET  /notices/:id/acknowledgements/count    the acknowledgements of a version, per channel
// Reading: settings, audit.read (the DPO, the auditor) or mdm.privacy.manage; writing: mdm.privacy.manage. Errors:
// 400 invalidRequest (details.keys), invalidNoticeSettings (details.tooLong, details.markup, details.maxima); 404
// noticeVersionNotFound; 409 noticeSettingsChanged (details.version: the version in force).
// =============================================================================

const read = requireAnyTenantCapability('settings', 'audit.read', 'mdm.privacy.manage');
const manage = requireTenantCapability('mdm.privacy.manage');

/** Versions listed by GET /notices. */
const HISTORY = 100;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The column of each setting. */
const COLUMN: Readonly<Record<NoticeSettingsKey, string>> = {
  controllerName: 'controller_name', controllerAddress: 'controller_address', dpoContact: 'dpo_contact', contact: 'contact',
  recipientsExtra: 'recipients_extra', introFr: 'intro_fr', introEn: 'intro_en',
};

type Handler = (req: Request, res: Response) => Promise<void>;
function h(fn: Handler) {
  return (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
}

const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);

const isPlatform = (v: unknown): v is NoticePlatform => (NOTICE_PLATFORMS as readonly unknown[]).includes(v);
const isOwnership = (v: unknown): v is Ownership => (OWNERSHIPS as readonly unknown[]).includes(v);
const isLocale = (v: unknown): v is NoticeLocale => (NOTICE_LOCALES as readonly unknown[]).includes(v);

async function canManage(req: Request): Promise<boolean> {
  return req.session.role === 'admin'
    || permissionService.userHasTenantCapability(req.session.userId!, req.tenantId!, 'mdm.privacy.manage');
}

/** The public page of the notice of the tenant (D6), null when this instance serves none (no device surface, no key). */
async function publicUrlOf(q: Knex | Knex.Transaction, tenantId: number): Promise<string | null> {
  const base = config.apple.mdmPublicBase;
  if (!base || !publicNoticeServed()) return null;
  const t = await q('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
  return t?.mdm_key ? `${base}/t/${t.mdm_key}/notice` : null;
}

async function settingsDto(q: Knex | Knex.Transaction, tenantId: number, manageable: boolean): Promise<NoticeSettingsDto> {
  const { settings, version } = await noticeSettingsOf(q, tenantId);
  const row = await q('tenant_notice_settings').where({ tenant_id: tenantId }).first('updated_at', 'updated_by') as
    { updated_at: Date; updated_by: number | null } | undefined;
  const missing = noticeCompleteness(settings);
  const stage = instanceStage();
  return {
    settings, version, updatedAt: iso(row?.updated_at), updatedBy: row?.updated_by === null || row?.updated_by === undefined ? null : Number(row.updated_by),
    missing, stage, enrollmentRefused: stage !== 'lab' && missing.length > 0, publicUrl: await publicUrlOf(q, tenantId), canManage: manageable,
  };
}

const SettingsBody = z.object({
  settings: z.record(z.string().max(64), z.unknown()).refine((v) => Object.keys(v).length <= 16, 'too many settings'),
  baseVersion: z.number().int().min(0).optional(),
}).strict();

/** The settings of a body, normalized (normalizeNoticeSetting) then checked: 400 when one is not acceptable. */
function settingsOfBody(given: Record<string, unknown>): Partial<NoticeSettings> {
  const normalized: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(given)) {
    normalized[k] = typeof v === 'string' && (NOTICE_SETTINGS_KEYS as string[]).includes(k) ? normalizeNoticeSetting(k as NoticeSettingsKey, v) : v;
  }
  const e = noticeSettingsErrors(normalized);
  if (Object.keys(given).length === 0 || e.unknown.length || e.invalid.length) {
    const keys = [...e.unknown, ...e.invalid];
    throw new AppError(400, `Settings of the notice: ${keys.length ? `unknown or not a text: ${keys.join(', ')}` : 'none given'}`, 'invalidRequest', { keys });
  }
  if (e.tooLong.length || e.markup.length) {
    throw new AppError(400, `Settings of the notice not accepted: ${[...e.tooLong, ...e.markup].join(', ')}`, 'invalidNoticeSettings', {
      tooLong: e.tooLong, markup: e.markup,
      maxima: Object.fromEntries(e.tooLong.map((k) => [k, NOTICE_SETTINGS_FIELDS[k].max])),
    });
  }
  return normalized as Partial<NoticeSettings>;
}

type VersionRow = {
  id: string; platform: NoticePlatform; ownership: Ownership; locale: NoticeLocale; content_sha256: string; generated_at: Date;
  superseded_at: Date | null; settings_version: number; retention_version: number; generator_version: number; profile_version: number | null;
  content?: unknown;
};

const VERSION_COLS = ['v.id', 'v.platform', 'v.ownership', 'v.locale', 'v.content_sha256', 'v.generated_at', 'v.superseded_at', 'v.settings_version',
  'v.retention_version', 'v.generator_version', 'p.version as profile_version'];

function versionsQuery(tenantId: number): Knex.QueryBuilder {
  return db('notice_versions as v')
    .leftJoin('privacy_profile_versions as p', function joinProfile() {
      this.on('p.tenant_id', '=', 'v.tenant_id').andOn('p.id', '=', 'v.privacy_profile_version_id');
    })
    .where('v.tenant_id', tenantId);
}

/** The acknowledgements of these versions. */
async function ackCounts(tenantId: number, ids: string[]): Promise<Map<string, number>> {
  if (!ids.length) return new Map();
  const rows = await db('notice_acknowledgements').where({ tenant_id: tenantId }).whereIn('notice_version_id', ids)
    .groupBy('notice_version_id').select('notice_version_id').count({ n: '*' }) as Array<{ notice_version_id: string; n: string | number }>;
  return new Map(rows.map((r) => [String(r.notice_version_id), Number(r.n)]));
}

function versionDto(r: VersionRow, acks: Map<string, number>): NoticeVersionDto {
  return {
    id: String(r.id), platform: r.platform, ownership: r.ownership, locale: r.locale, sha256: String(r.content_sha256).trim(),
    generatedAt: iso(r.generated_at)!, supersededAt: iso(r.superseded_at),
    profileVersion: r.profile_version === null || r.profile_version === undefined ? null : Number(r.profile_version),
    settingsVersion: Number(r.settings_version), retentionVersion: Number(r.retention_version), generatorVersion: Number(r.generator_version),
    acknowledgements: acks.get(String(r.id)) ?? 0, displayed: noticeDisplayed(r.platform, r.ownership),
  };
}

/** The text of a version (the CHECK notice_versions_content_shape guarantees its shape; a section is read defensively). */
function contentDto(v: unknown): NoticeContentDto {
  const c = (typeof v === 'string' ? JSON.parse(v) : v) as Record<string, unknown>;
  const sections = Array.isArray(c.sections) ? c.sections as Array<Record<string, unknown>> : [];
  return {
    title: String(c.title ?? ''),
    sections: sections.map((s) => ({
      heading: String(s?.heading ?? ''), paragraphs: Array.isArray(s?.paragraphs) ? (s.paragraphs as unknown[]).map((p) => String(p)) : [],
    })),
    consentSummary: String(c.consentSummary ?? ''),
    contact: typeof c.contact === 'string' ? c.contact : null,
  };
}

/** An optional filter of the query: absent, or one of `values` (else 400). */
function filterOf<T extends string>(query: Request['query'], name: string, ok: (v: unknown) => v is T): T | undefined {
  const v = query[name];
  if (v === undefined || v === '') return undefined;
  if (!ok(v)) throw new AppError(400, `Unknown ${name}`, 'invalidRequest', { keys: [name] });
  return v;
}

export function createNoticeRouter(): Router {
  const router = Router();

  router.get('/notice-settings', read, h(async (req, res) => {
    res.json({ data: await settingsDto(db, req.tenantId!, await canManage(req)) });
  }));

  router.put('/notice-settings', manage, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const userId = Number(req.session.userId);
    const body = SettingsBody.safeParse(req.body ?? {});
    if (!body.success) {
      const i = body.error.issues[0];
      throw new AppError(400, `${i?.path.join('.') || 'request'}: ${i?.message ?? 'invalid'}`, 'invalidRequest');
    }
    const given = settingsOfBody(body.data.settings);
    const auditCtx = await audit.fromRequest(req, tenantId);
    const changed = await db.transaction(async (trx) => {
      const cur = await trx('tenant_notice_settings').where({ tenant_id: tenantId }).forUpdate().first('version') as { version: number } | undefined;
      const before = await noticeSettingsOf(trx, tenantId);
      const baseVersion = cur ? Number(cur.version) : 0;
      if (body.data.baseVersion !== undefined && body.data.baseVersion !== baseVersion) {
        throw new AppError(409, `The settings of the notice changed meanwhile (version ${baseVersion})`, 'noticeSettingsChanged', { version: baseVersion });
      }
      const next: NoticeSettings = { ...before.settings };
      const keys: NoticeSettingsKey[] = [];
      for (const k of NOTICE_SETTINGS_KEYS) {
        if (!Object.prototype.hasOwnProperty.call(given, k)) continue;
        const v = given[k] ?? null;
        if (v !== before.settings[k]) { next[k] = v; keys.push(k); }
      }
      if (keys.length === 0) return null;
      const columns = Object.fromEntries(NOTICE_SETTINGS_KEYS.map((k) => [COLUMN[k], next[k]]));
      let version: number;
      if (cur) {
        // The trigger tenant_notice_settings_version moves the version and the instant.
        const [row] = await trx('tenant_notice_settings').where({ tenant_id: tenantId })
          .update({ ...columns, updated_by: userId }, ['version']) as Array<{ version: number }>;
        version = Number(row.version);
      } else {
        const rows = await trx('tenant_notice_settings').insert({ tenant_id: tenantId, ...columns, updated_by: userId })
          .onConflict('tenant_id').ignore().returning(['version']) as Array<{ version: number }>;
        // Another first change of the same tenant committed meanwhile.
        if (!rows.length) throw new AppError(409, 'The settings of the notice changed meanwhile', 'noticeSettingsChanged', { version: null });
        version = Number(rows[0].version);
      }
      const missing = noticeCompleteness(next);
      await audit.appendInTx(trx, {
        tenantId, action: 'privacy.notice_settings_changed', target: { type: 'notice_settings', id: String(tenantId) },
        // The keys changed, never their values (a contact may name a person).
        details: { version, baseVersion, changed: keys, complete: missing.length === 0, missing, stage: instanceStage() },
      }, auditCtx);
      // The notices tell these settings: generated again once the change is committed.
      await requestNoticeRegeneration(trx, tenantId);
      return keys;
    });
    const out: NoticeSettingsDto = { ...await settingsDto(db, tenantId, true), changed: changed !== null };
    res.json({ data: out });
  }));

  router.get('/notices', read, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const platform = filterOf(req.query, 'platform', isPlatform);
    const ownership = filterOf(req.query, 'ownership', isOwnership);
    const locale = filterOf(req.query, 'locale', isLocale);
    const filtered = (qb: Knex.QueryBuilder): Knex.QueryBuilder => {
      if (platform) qb.where('v.platform', platform);
      if (ownership) qb.where('v.ownership', ownership);
      if (locale) qb.where('v.locale', locale);
      return qb;
    };
    const current = await filtered(versionsQuery(tenantId)).whereNull('v.superseded_at')
      .orderBy([{ column: 'v.platform' }, { column: 'v.ownership' }, { column: 'v.locale' }])
      .select([...VERSION_COLS, 'v.content']) as VersionRow[];
    const history = await filtered(versionsQuery(tenantId)).orderBy([{ column: 'v.generated_at', order: 'desc' }, { column: 'v.id' }])
      .limit(HISTORY).select(VERSION_COLS) as VersionRow[];
    const acks = await ackCounts(tenantId, [...new Set([...current, ...history].map((r) => String(r.id)))]);
    const out: NoticesDto = {
      current: current.map((r) => ({ ...versionDto(r, acks), content: contentDto(r.content) })),
      history: history.map((r) => versionDto(r, acks)),
      publicUrl: await publicUrlOf(db, tenantId),
    };
    res.json({ data: out });
  }));

  router.get('/notices/preview', read, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const { platform, ownership, locale } = req.query;
    const bad = [['platform', isPlatform(platform)], ['ownership', isOwnership(ownership)], ['locale', isLocale(locale)]]
      .filter(([, ok]) => !ok).map(([k]) => k as string);
    if (bad.length || !isPlatform(platform) || !isOwnership(ownership) || !isLocale(locale)) {
      throw new AppError(400, `platform, ownership and locale are required: ${bad.join(', ')}`, 'invalidRequest', { keys: bad });
    }
    const t = await db('tenants').where({ id: tenantId }).first('name') as { name: string } | undefined;
    if (!t) throw new AppError(404, 'Tenant not found', 'notFound');
    const now = await generateNoticeNow(db, tenantId, platform, ownership, locale, String(t.name));
    const out: NoticePreviewDto = {
      platform, ownership, locale, content: contentDto(now.content), missing: noticeCompleteness(now.settings.settings),
      displayed: noticeDisplayed(platform, ownership),
    };
    res.json({ data: out });
  }));

  router.get('/notices/:id/acknowledgements/count', read, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = String(req.params.id ?? '');
    if (!UUID_RE.test(id)) throw new AppError(404, 'Notice version not found', 'noticeVersionNotFound');
    const versionId = id.toLowerCase();
    const v = await db('notice_versions').where({ tenant_id: tenantId, id: versionId }).first('id');
    if (!v) throw new AppError(404, 'Notice version not found', 'noticeVersionNotFound');
    const rows = await db('notice_acknowledgements').where({ tenant_id: tenantId, notice_version_id: versionId })
      .groupBy('channel').select('channel').count({ n: '*' }) as Array<{ channel: string; n: string | number }>;
    const byChannel = Object.fromEntries(NOTICE_ACK_CHANNELS.map((c) => [c, 0])) as Record<NoticeAckChannel, number>;
    for (const r of rows) if ((NOTICE_ACK_CHANNELS as readonly string[]).includes(r.channel)) byChannel[r.channel as NoticeAckChannel] = Number(r.n);
    const out: NoticeAcknowledgementCountDto = { versionId, total: Object.values(byChannel).reduce((a, b) => a + b, 0), byChannel };
    res.json({ data: out });
  }));

  return router;
}
