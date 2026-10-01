// The server's vault of secrets (docs: coffre-secrets.md). Importing this
// module registers the core's sealed columns (coreSecrets.ts). index.ts calls
// vaultConfigErrors() before anything touches the database, registerVaultJobs()
// with the other registries, then vault.init() and backfillLegacySecrets()
// after the boot guard, and vault.close() at shutdown.
import { registerCoreSecrets } from './coreSecrets';

registerCoreSecrets();

export {
  vault, VAULT_NAMESPACE, VaultStartupError, type SecretLocator, type VaultCallOptions, type ActorRef,
} from './vault';
export { VaultError, isVaultError, type VaultErrorCode } from './errors';
export {
  registerSecretColumn, registerInstanceSecretName, registerSecretReferenceHolder, findSecretRefs,
  type SecretColumnDef,
} from './registry';
export { vaultConfigErrors, readVaultConfig, type VaultConfig } from './config';
export { backfillLegacySecrets, BackfillError, type BackfillReport } from './backfill';
