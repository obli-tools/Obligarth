// The core's sealed columns and instance secret names (docs: coffre-secrets
// §4.2, §5.5), registered when the vault module is imported. A module
// registers its own (modules/devices.ts: device_licenses.license_key_enc).
import { allSecretFieldKeys, secretFieldsOf } from '../notifications/registry';
import { registerInstanceSecretName, registerSecretColumn } from './registry';
import { backfillObligateSettings } from './backfill';

let registered = false;

export function registerCoreSecrets(): void {
  if (registered) return;
  registered = true;

  // Second factor (TOTP): instance DEK, the identity context. A reseal never
  // bumps credential_version (phone keys survive the backfill and a DEK
  // rotation); a KEK loss disables the TOTP (the trigger then bumps it).
  registerSecretColumn({
    table: 'users', column: 'totp_secret_enc', pk: 'id', pkType: 'integer',
    tenantColumn: null, instanceContext: 'identity', encoding: 'utf8', owner: 'core.2fa',
    resealFlag: true,
    legacy: { kind: 'column', column: 'totp_secret', encoding: 'text' },
    onLoss: 'null', lossPatch: { totp_enabled: false },
  });
  // A TOTP setup in progress, kept 10 minutes in the session (transient:
  // outside the rotations, the verification and the recovery).
  registerSecretColumn({
    table: 'session', column: 'pending_totp_secret_enc', pk: 'user_id', pkType: 'integer',
    tenantColumn: null, encoding: 'utf8', owner: 'core.2fa', transient: true,
  });
  // SMTP servers: the DEK of the row's tenant; a platform server (tenant_id
  // NULL, class tenant_or_global) the instance DEK.
  registerSecretColumn({
    table: 'smtp_servers', column: 'password_enc', pk: 'id', pkType: 'integer',
    tenantColumn: 'tenant_id', tenantNullable: true, encoding: 'utf8', owner: 'core.smtp',
    legacy: { kind: 'column', column: 'password', encoding: 'text' },
    onLoss: 'null',
  });
  // Notification channels: the secret fields of the plugin, as one JSON
  // object; their names in secret_fields.
  registerSecretColumn({
    table: 'notification_channels', column: 'secrets_enc', pk: 'id', pkType: 'integer',
    tenantColumn: 'tenant_id', encoding: 'json', owner: 'core.notifications',
    legacy: {
      kind: 'json-fields', column: 'config',
      fieldsOf: (row) => secretFieldsOf(String(row.type ?? '')),
      candidates: () => allSecretFieldKeys(),
    },
    onLoss: 'null', lossPatch: { secret_fields: '[]' },
  });
  // Executor-only data of two-step approvals (bcrypt hash, image).
  registerSecretColumn({
    table: 'pending_approvals', column: 'sealed_payload_enc', pk: 'id', pkType: 'integer',
    tenantColumn: 'tenant_id', encoding: 'json', owner: 'core.approvals',
    legacy: { kind: 'column', column: 'sealed_payload', encoding: 'jsonb' },
    onLoss: 'null',
  });
  // Named secrets of the instance; the Obligate settings move there from
  // app_config.obligate_config.
  registerSecretColumn({
    table: 'instance_secrets', column: 'value_enc', pk: 'name', pkType: 'name',
    tenantColumn: null, instanceContext: 'none', encoding: 'utf8', owner: 'core.vault',
    legacy: { kind: 'custom', name: 'obligate_settings', run: backfillObligateSettings },
    onLoss: 'delete',
  });
  // Secrets referenced from documents ({"$secret": "<id>"}).
  registerSecretColumn({
    table: 'tenant_secrets', column: 'value_enc', pk: 'id', pkType: 'uuid',
    tenantColumn: 'tenant_id', encoding: 'binary', owner: 'core.vault',
    onLoss: 'delete',
  });

  registerInstanceSecretName('obligate_api_key', 'API key of this application in Obligate (outbound calls, SSO)');
  registerInstanceSecretName('obligate_inbound_secret', 'Secret Obligate presents on its calls to this server');
}
