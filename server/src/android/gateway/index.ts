// The gateway of this process: GoogleGateway in google and fake modes (same class), OffGateway otherwise.
import { asNone } from '../../db/context';
import { vault } from '../../vault';
import { androidConfig, type AndroidConfig } from '../config';
import { AndroidDisabledError } from './errors';
import { GoogleGateway } from './google';
import type { AndroidGateway } from './types';

/** Name of the instance secret holding the service account key (vault_key mode). */
export const GOOGLE_CREDENTIALS_SECRET = 'android_google_credentials';

/** Every method of the off gateway refuses (androidDisabled). */
export function offGateway(): AndroidGateway {
  const refuse = async (): Promise<never> => { throw new AndroidDisabledError(); };
  return new Proxy({ mode: 'off' } as AndroidGateway, {
    get(_target, prop) {
      if (prop === 'mode') return 'off';
      if (prop === 'health') return async () => ({ mode: 'off', identity: null, breaker: null, subscriptionPermission: null });
      if (prop === 'then') return undefined;
      return refuse;
    },
  }) as unknown as AndroidGateway;
}

/** The sealed key, opened in the context 'none' of the identity (never logged). */
export const loadSealedKey = (): Promise<string | null> =>
  asNone({ type: 'job', name: 'android.identity' }, () => vault.getInstanceSecret(GOOGLE_CREDENTIALS_SECRET));

export function createGateway(cfg: AndroidConfig, loadKey = loadSealedKey): AndroidGateway {
  if (cfg.mode === 'off') return offGateway();
  return new GoogleGateway(cfg, loadKey);
}

let current: AndroidGateway | null = null;

export function androidGateway(): AndroidGateway {
  if (!current) current = createGateway(androidConfig());
  return current;
}

/** Replaces the gateway of this process (start after configureAndroid, tests). */
export function setAndroidGateway(gw: AndroidGateway | null): void {
  current = gw;
}
