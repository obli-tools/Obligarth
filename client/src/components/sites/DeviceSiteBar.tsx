import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { MapPin, Pencil } from 'lucide-react';
import type { DeviceDetail } from '@obligarth/shared';
import { sitesApi } from '@/api/sites.api';
import { SitePickerDialog, useSiteChange } from '@/components/sites/siteUi';
import { anonymize } from '@/utils/anonymize';

// The site of a device, at the top of its record (lot P1-SITE §2.4): the site it is at, a link to its page, and the
// change (a searchable list). A site with a group then offers the guarded move into it (useSiteChange). In the
// device's own tenant only (a site is a tenant's).

export function DeviceSiteBar({ device, canChange, onChanged }: { device: DeviceDetail; canChange: boolean; onChanged: () => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const siteChange = useSiteChange(onChanged);
  const site = device.site ?? null;
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-xl bg-bg-secondary px-4 py-2.5 text-sm">
      <MapPin className="h-4 w-4 shrink-0 text-text-muted" />
      <span className="text-xs uppercase tracking-wider text-text-muted">{t('sites.field') || 'Site'}</span>
      {site ? (
        <Link to={`/sites/${site.id}`} className="min-w-0 truncate font-medium text-text-primary hover:text-accent">
          <span className="font-mono text-xs text-text-muted">{anonymize(site.code)}</span> {anonymize(site.name)}
        </Link>
      ) : (
        <span className="text-text-muted">{t('sites.none') || 'No site'}</span>
      )}
      {canChange && (
        <button type="button" onClick={() => setOpen(true)}
          className="ml-auto inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-text-muted hover:bg-bg-tertiary hover:text-text-primary coarse:min-h-10">
          <Pencil className="h-3.5 w-3.5" />{site ? (t('sites.change') || 'Change') : (t('sites.choose') || 'Choose a site')}
        </button>
      )}
      {siteChange.dialog}
      <SitePickerDialog open={open} onClose={() => setOpen(false)} value={site?.id ?? null}
        onPick={async (s) => {
          setOpen(false);
          if ((s?.id ?? null) === (site?.id ?? null)) return;
          await siteChange.change(() => sitesApi.setDeviceSite(device.id, s?.id ?? null), { single: true });
        }} />
    </div>
  );
}
