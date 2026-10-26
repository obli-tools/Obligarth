import { trCode } from '@/utils/apiError';

// The state of the delivery of an app, shown alike by the catalog (pages/AppsPage) and by the inventory of a device
// (mdm/DeviceAppsTab): one colour (StateBadge) and one label per state. The states of an artifact or of an AMAPI
// report take the catalog's labels (apps.delivery.*); only the states of a command of the bridge agent that no
// artifact has (sent, acknowledged, rejected, expired, cancelled) have labels of their own.

export type DeliveryTone = 'green' | 'gray' | 'amber' | 'red' | 'blue';

export const DELIVERY_TONE: Readonly<Record<string, DeliveryTone>> = {
  applied: 'green', pending: 'blue', delivering: 'blue', error: 'red', not_applicable: 'amber', removing: 'gray',
  sent: 'blue', acknowledged: 'green', rejected: 'red', expired: 'gray', cancelled: 'gray',
};

const CATALOG_STATES = new Set(['applied', 'pending', 'delivering', 'error', 'not_applicable', 'removing']);

export const deliveryTone = (state: string): DeliveryTone => DELIVERY_TONE[state] ?? 'gray';

export const deliveryLabel = (state: string): string => (CATALOG_STATES.has(state)
  ? trCode(`apps.delivery.${state}`, state)
  : trCode(`mdm.inventory.apps.delivery.${state}`, state));
