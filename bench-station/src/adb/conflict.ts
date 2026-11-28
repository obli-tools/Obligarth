import { execFile } from 'node:child_process';
import { powershellOut } from '../native';

/**
 * Obligarth bench station — the other adb on this PC, the Samsung driver, Smart Switch (lot BANC §5.5).
 *
 * A port of its own does not isolate USB: under Windows the WinUSB interface of a device is opened by ONE process. An
 * adb of Android Studio, scrcpy or a Samsung tool holding the phone makes it `offline` or absent for the station. At
 * start, and on any unexplained `offline` or disappearance, the station lists the `adb.exe` processes that are not its
 * own and the listener on 5037; one found ⇒ banner `adb_conflict` with « Arrêter ces processus » (explicit
 * confirmation: `adb -P 5037 kill-server`, then the processes are stopped).
 * Readings are made by one hidden PowerShell call (JSON); the verdicts are pure (tested).
 */

export interface ProcessInfo { pid: number; path: string | null; commandLine: string | null; name: string }

export interface EnvironmentReading {
  adb: ProcessInfo[];
  listener5037: number[];
  smartSwitch: boolean;
}

export interface ConflictVerdict {
  conflict: boolean;
  /** The foreign adb processes (path and pid, for the page). */
  foreign: Array<{ pid: number; path: string | null }>;
  listener5037: boolean;
}

const norm = (p: string | null): string => (p ?? '').replace(/\//g, '\\').toLowerCase();

/** Pure: which adb processes are not the station's (its adb.exe, on its own port). */
export function judgeConflict(r: EnvironmentReading, ownAdb: string | null, ownPort: number): ConflictVerdict {
  const own = norm(ownAdb);
  const foreign = r.adb.filter((p) => {
    const same = own !== '' && norm(p.path) === own;
    // Our binary started on another port (by hand, by an earlier run with another .ini) is still a foreign server.
    const otherPort = /\btcp:(\d+)\b/.exec(p.commandLine ?? '');
    return !same || (otherPort !== null && Number(otherPort[1]) !== ownPort);
  }).map((p) => ({ pid: p.pid, path: p.path }));
  const listener = r.listener5037.length > 0;
  return { conflict: foreign.length > 0 || listener, foreign, listener5037: listener };
}

const READ_SCRIPT = [
  "$adb = @(Get-CimInstance Win32_Process -Filter \"Name='adb.exe'\" | ForEach-Object { [pscustomobject]@{ pid = [int]$_.ProcessId; path = $_.ExecutablePath; commandLine = $_.CommandLine; name = $_.Name } })",
  '$l = @(); try { $l = @(Get-NetTCPConnection -LocalPort 5037 -State Listen -ErrorAction Stop | ForEach-Object { [int]$_.OwningProcess }) } catch { }',
  "$ss = @(Get-Process -Name 'SmartSwitchPC' -ErrorAction SilentlyContinue).Count -gt 0",
  '[pscustomobject]@{ adb = $adb; listener5037 = $l; smartSwitch = $ss } | ConvertTo-Json -Depth 4 -Compress',
].join('\n');

export function parseEnvironmentJson(text: string): EnvironmentReading {
  const v = JSON.parse(text.trim() || '{}') as { adb?: unknown; listener5037?: unknown; smartSwitch?: unknown };
  const arr = (x: unknown): unknown[] => (Array.isArray(x) ? x : x === null || x === undefined ? [] : [x]);
  const adb = arr(v.adb).map((p) => {
    const o = p as Record<string, unknown>;
    return { pid: Number(o.pid), path: typeof o.path === 'string' ? o.path : null, commandLine: typeof o.commandLine === 'string' ? o.commandLine : null, name: String(o.name ?? 'adb.exe') };
  }).filter((p) => Number.isInteger(p.pid) && p.pid > 0);
  const listener5037 = arr(v.listener5037).map(Number).filter((n) => Number.isInteger(n) && n > 0);
  return { adb, listener5037, smartSwitch: v.smartSwitch === true };
}

export async function readEnvironment(): Promise<EnvironmentReading> {
  if (process.platform !== 'win32') return { adb: [], listener5037: [], smartSwitch: false };
  try {
    return parseEnvironmentJson(await powershellOut(READ_SCRIPT, 20_000));
  } catch {
    return { adb: [], listener5037: [], smartSwitch: false };
  }
}

/** Stops processes by pid (after the technician's confirmation). */
export async function stopProcesses(pids: number[]): Promise<void> {
  const list = pids.filter((p) => Number.isInteger(p) && p > 0 && p !== process.pid);
  if (list.length === 0 || process.platform !== 'win32') return;
  await powershellOut(`Stop-Process -Id ${list.join(',')} -Force -ErrorAction SilentlyContinue`, 20_000).catch(() => '');
}

/**
 * The driver of the Samsung phones on USB. Windows 10 and 11 drive a phone in USB debugging with their OWN generic
 * driver (WinUSB, "ADB Interface", announced by the phone itself): Samsung's driver is not needed, and its absence is
 * not a problem. A problem is a Samsung USB device (VID 04E8) that Windows sees with NO working driver (a status other
 * than OK: no driver, error). Pure: the lines are `<status>|<instance id>`.
 */
export function samsungDriverMissing(lines: string): boolean {
  return lines.split(/\r?\n/).some((l) => {
    const [status, id] = l.trim().split('|');
    return /^USB\\VID_04E8&/i.test(id ?? '') && (status ?? '').trim().toUpperCase() !== 'OK';
  });
}

const DRIVER_SCRIPT = "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'USB\\VID_04E8&*' } | ForEach-Object { '' + $_.Status + '|' + $_.InstanceId }";

/** true: every Samsung device on USB has a working driver (or none is plugged); false: one lacks it; null: unknown. */
export async function readSamsungDriver(): Promise<boolean | null> {
  if (process.platform !== 'win32') return null;
  try {
    return !samsungDriverMissing(await powershellOut(DRIVER_SCRIPT, 20_000));
  } catch {
    return null;
  }
}

/**
 * The serial numbers of the Samsung phones Windows sees on USB (`pnputil /enum-devices /connected`, VID 04E8): the
 * instance id of the parent USB device ends with the phone's serial (its ADB serial). Interfaces (`&MI_xx`) are left
 * out. Pure (its output is localised: only the instance ids are read).
 */
export function samsungUsbSerials(pnputilOutput: string): string[] {
  const out = new Set<string>();
  for (const m of pnputilOutput.matchAll(/USB\\VID_04E8&PID_[0-9A-F]{4}\\([A-Za-z0-9]{6,64})\b/gi)) out.add(m[1].toUpperCase());
  return [...out];
}

/** The Samsung phones on USB (null: unknown, not Windows or pnputil unavailable). */
export function readSamsungUsb(): Promise<string[] | null> {
  if (process.platform !== 'win32') return Promise.resolve(null);
  return new Promise((resolve) => {
    execFile('pnputil', ['/enum-devices', '/connected'], { windowsHide: true, timeout: 20_000, maxBuffer: 8 * 1024 * 1024, encoding: 'latin1' }, (err, out) => {
      resolve(err && !out ? null : samsungUsbSerials(String(out)));
    });
  });
}

/**
 * §6.1: the Samsung phones Windows sees on USB that adb does not list at all (any state): USB debugging off, Auto Blocker (One UI 6+, on
 * by default), or USB debugging blocked by a policy (Knox, left by a former MDM). Compared case-insensitively.
 */
export function usbUnseenByAdb(usb: string[] | null, adbSerials: string[]): string[] {
  if (!usb) return [];
  const seen = new Set(adbSerials.map((s) => s.toUpperCase()));
  return usb.filter((s) => !seen.has(s));
}
