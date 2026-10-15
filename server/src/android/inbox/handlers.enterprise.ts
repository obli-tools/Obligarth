// Handler of the ENTERPRISE_UPGRADE notifications (section 6.3): a managed Google Play Accounts enterprise upgraded
// to a managed Google domain. The device families (ENROLLMENT, STATUS_REPORT, COMMAND, USAGE_LOGS) register their
// handlers with the lots that bring the device tables (AN-C1, AN-D).
import { registerAndroidEventHandler } from './handlers';
import { EnterpriseUpgradeSchema } from './schemas';

let registered = false;

export function registerEnterpriseHandlers(): void {
  if (registered) return;
  registered = true;
  registerAndroidEventHandler({
    type: 'amapi.enterprise_upgrade',
    payload: EnterpriseUpgradeSchema,
    async handle(ctx) {
      if (ctx.event.payload.upgradeState !== 'UPGRADE_STATE_SUCCEEDED') return;
      const n = await ctx.trx('android_enterprises')
        .where({ id: ctx.enterpriseId })
        .where((w) => w.whereNull('enterprise_type').orWhereNot('enterprise_type', 'MANAGED_GOOGLE_DOMAIN'))
        .update({ enterprise_type: 'MANAGED_GOOGLE_DOMAIN', updated_at: ctx.trx.fn.now() });
      if (n > 0) {
        ctx.audit({
          tenantId: ctx.tenantId, action: 'android.enterprise_upgraded',
          target: { type: 'android_enterprise', id: String(ctx.enterpriseId) }, details: { enterpriseId: ctx.enterpriseId },
        });
      }
    },
  });
}
