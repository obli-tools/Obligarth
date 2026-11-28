import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Obligarth bench station — where its local files live (lot BANC §5.2).
 *
 * Everything under %LOCALAPPDATA%\Obligarth: machine-local and per user, never %APPDATA% (which may roam to other
 * computers with the profile — the station token must not). One station is one Windows user on one PC (§6.9).
 *   bench-ui\                 the Edge profile of the application window
 *   platform-tools-<ver>\     adb.exe and its two DLLs, downloaded and checked (§5.5)
 *   adb-home\                 the home given to the adb process only
 *   apk-cache\                the agent's APK, by SHA-256
 *   bench-station.json        the station token, protected by DPAPI (CurrentUser)
 *   bench-history.json        the local history, protected by DPAPI
 *   bench-error.log           internal errors (redacted)
 *   bench.lock                the single-instance lock
 */
export const APP_DIR = 'Obligarth';

export function localDataDir(env: NodeJS.ProcessEnv = process.env): string {
  const local = (env.LOCALAPPDATA ?? '').trim();
  if (local) return join(local, APP_DIR);
  if (process.platform === 'win32') return join(homedir(), 'AppData', 'Local', APP_DIR);
  const xdg = (env.XDG_STATE_HOME ?? '').trim();
  return join(xdg || join(homedir(), '.local', 'state'), APP_DIR);
}

export const stationFile = (env: NodeJS.ProcessEnv = process.env): string => join(localDataDir(env), 'bench-station.json');
export const historyFile = (env: NodeJS.ProcessEnv = process.env): string => join(localDataDir(env), 'bench-history.json');
export const errorLogFile = (env: NodeJS.ProcessEnv = process.env): string => join(localDataDir(env), 'bench-error.log');
export const lockFile = (env: NodeJS.ProcessEnv = process.env): string => join(localDataDir(env), 'bench.lock');
export const uiProfileDir = (env: NodeJS.ProcessEnv = process.env): string => join(localDataDir(env), 'bench-ui');
export const adbHomeDir = (env: NodeJS.ProcessEnv = process.env): string => join(localDataDir(env), 'adb-home');
export const apkCacheDir = (env: NodeJS.ProcessEnv = process.env): string => join(localDataDir(env), 'apk-cache');
export const platformToolsDir = (version: string, env: NodeJS.ProcessEnv = process.env): string =>
  join(localDataDir(env), `platform-tools-${version}`);
