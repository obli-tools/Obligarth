import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ExternalLink, Eye, Lock, MapPin, Navigation, RefreshCw } from 'lucide-react';
import type { DeviceDetail, DeviceLocationPoint, DeviceLocations } from '@obligarth/shared';
import { SocketEvents } from '@obligarth/shared';
import { appleApi } from '@/api/apple.api';
import { mdmApi } from '@/api/mdm.api';
import { registerSocketListener } from '@/socket/socketListeners';
import { Button } from '@/components/common/Button';
import { formatDateTime, shortAge } from '@/components/mdm/PlatformIcon';
import { CopyButton, InfoCard, InfoRow, InfoRows } from '@/components/mdm/ui/InfoCard';
import { anonymize, isAnonymousMode } from '@/utils/anonymize';
import { apiErrorMessage, trCode } from '@/utils/apiError';
import { openExternal } from '@/utils/openExternal';
import { QuickActionButton } from './DeviceHero';
import type { UnifiedAction } from './useDeviceActions';

// Where the device was last seen (lost mode only, SEC-05; lost_mode_locations, kept a few days, never for a personal
// device): the coordinates and their accuracy, links to OpenStreetMap and to the phone's maps app, and — only on an
// explicit click, since a map tile tells openstreetmap.org where the device is — a small tile preview with the
// accuracy circle. No map library. The positions are read only on an explicit request and only while the lost mode is
// on: each read is a critical access the server writes to the audit log first. Anonymous mode masks the coordinates
// and hides the map and its links.

const TILE = 256;
const ZOOM = 16;
const coord = (n: number): string => n.toFixed(6);

const osmUrl = (p: DeviceLocationPoint): string =>
  `https://www.openstreetmap.org/?mlat=${coord(p.latitude)}&mlon=${coord(p.longitude)}#map=17/${coord(p.latitude)}/${coord(p.longitude)}`;

/** 3×3 OpenStreetMap tiles around the point, centred by a CSS translation, the marker and the accuracy circle on top. */
function MapPreview({ point }: { point: DeviceLocationPoint }) {
  const { t } = useTranslation();
  const [failed, setFailed] = useState(false);
  const n = 2 ** ZOOM;
  const latRad = (point.latitude * Math.PI) / 180;
  const xf = ((point.longitude + 180) / 360) * n;
  const yf = ((1 - Math.log(Math.tan(latRad) + 1 / Math.cos(latRad)) / Math.PI) / 2) * n;
  const cx = Math.floor(xf);
  const cy = Math.floor(yf);
  // The point inside the centre tile, in pixels.
  const px = (xf - cx) * TILE;
  const py = (yf - cy) * TILE;
  // Metres per pixel at this latitude and zoom (Web Mercator).
  const mpp = (156543.03 * Math.cos(latRad)) / n;
  const radius = point.horizontalAccuracy ? Math.min(600, point.horizontalAccuracy / mpp) : 0;
  const tiles: Array<{ key: string; x: number; y: number; left: number; top: number }> = [];
  for (let dy = -1; dy <= 1; dy += 1) {
    for (let dx = -1; dx <= 1; dx += 1) {
      const y = cy + dy;
      if (y < 0 || y >= n) continue;
      const x = (((cx + dx) % n) + n) % n;
      tiles.push({ key: `${dx}:${dy}`, x, y, left: (dx + 1) * TILE, top: (dy + 1) * TILE });
    }
  }
  return (
    <div className="relative h-56 w-full overflow-hidden rounded-lg border border-border bg-bg-tertiary sm:h-64">
      {failed ? (
        <p className="flex h-full items-center justify-center px-4 text-center text-xs text-text-muted">
          {t('deviceSummary.location.previewFailed') || 'The map could not be loaded (network or security policy). Use the OpenStreetMap link.'}
        </p>
      ) : (
        <>
          <div className="absolute left-1/2 top-1/2" style={{ width: TILE * 3, height: TILE * 3, transform: `translate(${-(TILE + px)}px, ${-(TILE + py)}px)` }}>
            {tiles.map((tl) => (
              <img
                key={tl.key}
                src={`https://tile.openstreetmap.org/${ZOOM}/${tl.x}/${tl.y}.png`}
                alt=""
                width={TILE}
                height={TILE}
                draggable={false}
                loading="lazy"
                onError={() => setFailed(true)}
                className="absolute max-w-none select-none"
                style={{ left: tl.left, top: tl.top, width: TILE, height: TILE }}
              />
            ))}
          </div>
          {radius > 4 && (
            <span
              className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-accent bg-accent/15"
              style={{ width: radius * 2, height: radius * 2 }}
              aria-hidden
            />
          )}
          <MapPin className="pointer-events-none absolute left-1/2 top-1/2 h-8 w-8 -translate-x-1/2 -translate-y-full fill-red-500 text-white drop-shadow" aria-hidden />
          <a
            href="https://www.openstreetmap.org/copyright"
            onClick={(e) => { e.preventDefault(); void openExternal('https://www.openstreetmap.org/copyright'); }}
            target="_blank"
            rel="noopener noreferrer"
            className="absolute bottom-0 right-0 rounded-tl bg-bg-secondary/85 px-1.5 py-0.5 text-[10px] text-text-secondary hover:underline"
          >
            {t('deviceSummary.location.attribution') || '© OpenStreetMap contributors'}
          </a>
        </>
      )}
    </div>
  );
}

export function LocationCard({ device, locate, id, className, reveal, onRevealed }: {
  device: DeviceDetail;
  /** The locate action of the record (Apple: a DeviceLocation command; Android: automatic in lost mode). */
  locate: UnifiedAction;
  id?: string;
  className?: string;
  /** A request to show the positions now (the lost mode banner; a timestamp, 0: none), consumed by onRevealed. */
  reveal?: number;
  onRevealed?: () => void;
}) {
  const { t } = useTranslation();
  const personal = device.ownership === 'personal';
  const unenrolled = device.enrollmentState === 'unenrolled';
  // The positions exist only during the lost mode (SEC-05): the server refuses them otherwise, the card does not ask.
  const readable = !personal && !unenrolled && device.lostModeState !== 'off';
  const anon = isAnonymousMode();
  // Read only on an explicit request (each read is a journaled access), never by itself on display.
  const [shown, setShown] = useState(false);
  const [data, setData] = useState<DeviceLocations | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState(false);

  const load = useCallback(() => {
    if (!readable) return;
    setError(null);
    mdmApi.locations(device.id, 20).then((d) => { setData(d); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, [device.id, readable]);
  // Another device, the lost mode ended or the device left management: nothing shown until asked again.
  useEffect(() => { setShown(false); setData(null); setError(null); setPreview(false); }, [device.id, readable]);
  const show = () => { setShown(true); load(); };
  // The banner's "See the location": an explicit request too, consumed at once.
  useEffect(() => {
    if (!reveal) return;
    if (readable) { setShown(true); load(); }
    onRevealed?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reveal]);
  // While shown, an Apple DeviceLocation acknowledged for this device brings a position: read again then only. The
  // event names the commands, not their type: one look at each (never a read of the positions for another command).
  useEffect(() => {
    if (!shown || device.platform === 'android') return undefined;
    return registerSocketListener(SocketEvents.MDM_COMMAND_CHANGED, (p: { commandIds?: string[]; deviceIds?: number[] }) => {
      if (!Array.isArray(p?.deviceIds) || !p.deviceIds.map(Number).includes(device.id)) return;
      const ids = (Array.isArray(p.commandIds) ? p.commandIds : []).slice(0, 5);
      void Promise.all(ids.map((cid) => appleApi.command(String(cid)).catch(() => null))).then((found) => {
        const located = found.some((r) => r?.command.requestType === 'DeviceLocation'
          && r.targets.some((x) => x.deviceId === device.id && x.state === 'acknowledged'));
        if (located) load();
      });
    });
  }, [shown, device.id, device.platform, load]);

  const title = t('deviceSummary.location.title') || 'Location';
  if (personal) {
    return (
      <InfoCard id={id} icon={MapPin} title={title} className={className}>
        <p className="flex items-start gap-2 text-sm text-text-muted">
          <Lock className="mt-0.5 w-4 h-4 shrink-0" aria-hidden />
          {t('deviceSummary.location.personal') || 'Never located: this is a personal device.'}
        </p>
      </InfoCard>
    );
  }

  const last = data?.points[0] ?? null;
  const older = data?.points.slice(1) ?? [];
  const unavailableText = (code: DeviceLocations['unavailable']): string => {
    if (code === 'unenrolled') return t('deviceSummary.location.unenrolled') || 'Out of management: no position is shown.';
    if (code === 'lostModeOff') return t('deviceSummary.location.lostModeOff') || 'Positions exist only while the lost mode is on.';
    if (code === 'locationDisabledByPrivacy') {
      return t('deviceSummary.location.locationDisabledByPrivacy') || "The privacy profile of this device's ownership does not allow locating it: no position is shown.";
    }
    return t('deviceSummary.location.capabilityMissing') || 'Your team does not hold the lost mode capability on this device: its positions are not shown.';
  };
  /** Coordinates as shown: masked in anonymous mode (the copy button keeps the real value, as for the serial number). */
  const shownCoord = (pt: DeviceLocationPoint): string => anonymize(`${coord(pt.latitude)}, ${coord(pt.longitude)}`);
  return (
    <InfoCard
      id={id}
      icon={MapPin}
      title={title}
      className={className}
      action={readable && shown ? (
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="rounded p-1.5 text-text-muted hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
      ) : undefined}
    >
      {!readable ? (
        <p className="text-sm text-text-muted">{unavailableText(unenrolled ? 'unenrolled' : 'lostModeOff')}</p>
      ) : !shown ? (
        <div className="space-y-2">
          <Button size="sm" variant="secondary" onClick={show} className="gap-1.5">
            <Eye className="w-4 h-4" aria-hidden />{t('deviceSummary.location.show') || 'Show the positions'}
          </Button>
          <p className="text-[11px] text-text-muted">{t('deviceSummary.location.showHint') || 'Each look at the positions is written to the audit log.'}</p>
        </div>
      ) : error ? <p className="text-sm text-red-400">{error}</p>
        : data === null ? (
          <div className="space-y-2" aria-busy>
            <div className="h-5 w-2/3 animate-pulse rounded bg-bg-tertiary" />
            <div className="h-4 w-1/2 animate-pulse rounded bg-bg-tertiary" />
          </div>
        ) : !data.available ? (
          <p className="text-sm text-text-muted">{unavailableText(data.unavailable)}</p>
        ) : !last ? (
          <div className="space-y-1">
            <p className="text-sm text-text-secondary">{t('deviceSummary.location.none') || 'No position known.'}</p>
            <p className="text-xs text-text-muted">{t('deviceSummary.location.noneHint') || 'Positions exist only in lost mode: ask with « Locate » (Apple), or they arrive by themselves (Android).'}</p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="group flex flex-wrap items-center gap-x-2">
              <span className="font-mono text-base text-text-primary break-all">{shownCoord(last)}</span>
              <CopyButton value={`${coord(last.latitude)}, ${coord(last.longitude)}`} label={t('deviceSummary.location.coordinates') || 'Coordinates'} />
            </div>
            <InfoRows>
              {last.horizontalAccuracy !== null && <InfoRow label={t('deviceSummary.location.accuracy') || 'Accuracy'} value={`± ${Math.round(last.horizontalAccuracy)} m`} />}
              {last.altitude !== null && <InfoRow label={t('deviceSummary.location.altitude') || 'Altitude'} value={`${Math.round(last.altitude)} m`} />}
              {last.speed !== null && <InfoRow label={t('deviceSummary.location.speed') || 'Speed'} value={`${Math.round(last.speed * 3.6)} km/h`} />}
              <InfoRow
                label={t('deviceSummary.location.observed') || 'Observed'}
                value={<span><span className="text-text-primary">{shortAge(last.observedAt)}</span><span className="ml-2 text-xs text-text-muted">{formatDateTime(last.observedAt)}</span></span>}
              />
              <InfoRow label={t('deviceSummary.location.origin') || 'Source'} value={trCode(`deviceSummary.location.source.${last.source}`, last.source)} />
            </InfoRows>
            {anon ? (
              // Anonymous mode (a shared screen, a demonstration): no map nor link that would show the place.
              <p className="text-[11px] text-text-muted">{t('deviceSummary.location.anonymous') || 'Anonymous mode: the map and its links are hidden.'}</p>
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
                  <a
                    href={osmUrl(last)}
                    onClick={(e) => { e.preventDefault(); void openExternal(osmUrl(last)); }}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-accent hover:underline coarse:min-h-10"
                  >
                    <ExternalLink className="w-4 h-4" aria-hidden />{t('deviceSummary.location.openOsm') || 'Open in OpenStreetMap'}
                  </a>
                  {/* The maps app of a phone or tablet (geo: URI). */}
                  <a href={`geo:${coord(last.latitude)},${coord(last.longitude)}`} className="hidden items-center gap-1 text-accent hover:underline coarse:inline-flex coarse:min-h-10">
                    <Navigation className="w-4 h-4" aria-hidden />{t('deviceSummary.location.openMaps') || 'Open in maps'}
                  </a>
                  <button type="button" onClick={() => setPreview((v) => !v)} className="inline-flex items-center gap-1 text-accent hover:underline coarse:min-h-10" aria-expanded={preview}>
                    <MapPin className="w-4 h-4" aria-hidden />
                    {preview ? (t('deviceSummary.location.hidePreview') || 'Hide the map') : (t('deviceSummary.location.showPreview') || 'Show a map preview')}
                  </button>
                </div>
                {!preview && <p className="text-[11px] text-text-muted">{t('deviceSummary.location.previewHint') || 'The preview loads map tiles from openstreetmap.org, which then learns this position.'}</p>}
                {preview && <MapPreview key={`${last.latitude},${last.longitude}`} point={last} />}
              </>
            )}
            {older.length > 0 && (
              <details className="group/hist text-sm">
                <summary className="cursor-pointer select-none text-xs text-text-secondary hover:text-text-primary coarse:py-2">
                  {t('deviceSummary.location.history') || 'Earlier positions'} ({older.length})
                </summary>
                <ul className="mt-2 divide-y divide-border/60">
                  {older.map((pt) => (
                    <li key={`${pt.observedAt}-${pt.latitude}-${pt.longitude}`} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 py-1.5 text-xs">
                      <span className="text-text-muted">{formatDateTime(pt.observedAt)}</span>
                      {anon ? <span className="font-mono text-text-secondary break-all">{shownCoord(pt)}</span> : (
                        <a href={osmUrl(pt)} onClick={(e) => { e.preventDefault(); void openExternal(osmUrl(pt)); }} target="_blank" rel="noopener noreferrer"
                          className="font-mono text-accent hover:underline break-all">{shownCoord(pt)}</a>
                      )}
                      {pt.horizontalAccuracy !== null && <span className="text-text-muted">± {Math.round(pt.horizontalAccuracy)} m</span>}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )}

      <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-border pt-3">
        {!locate.hidden && <QuickActionButton action={locate} />}
        {/* The reason of the action (Android: "sends its position by itself") never contradicts a refusal of the privacy
            profile, which the body already tells. */}
        {!locate.available && locate.reasonLabel && data?.unavailable !== 'locationDisabledByPrivacy'
          && <span className="min-w-0 flex-1 text-[11px] text-text-muted">{locate.reasonLabel}</span>}
        {data && (
          <span className="w-full text-[11px] text-text-muted">
            {t('deviceSummary.location.retention', { count: data.retentionDays })
              || `Positions are kept ${data.retentionDays} ${data.retentionDays === 1 ? 'day' : 'days'}, in lost mode only.`}
          </span>
        )}
      </div>
    </InfoCard>
  );
}
