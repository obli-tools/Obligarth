/**
 * Obligarth bench station — build the station as a single Windows executable (lot BANC §5.2, §5.9), on the model of
 * the bench of Obliwan (server/src/bench/build.mjs there).
 *
 *   node bench-station/build.mjs --bundle-only [--out <dir>]     the bundle alone (checks the import graph); no exe
 *   node bench-station/build.mjs --out <empty dir> [--dev]       exe (SEA, GUI subsystem, proven), product.wxs, VERSION
 *   node bench-station/build.mjs --out <empty dir> --release --signer <signing script>
 *                                                                the whole chain: exe, SIGN, verify, MSI, SIGN, verify
 *   node bench-station/build.mjs --check-sea <exe> [--blob <blob>]
 *
 * ┌─ SIGNING: OUTSIDE THE REPOSITORY, AND THE BUILD STOPS IF IT FAILS ───────┐
 * │ The station's exe and MSI are signed with the certificate of the Obli*  │
 * │ suite (Certum SimplySign, cloud, unlocked by a TOTP — there is no .pfx  │
 * │ anywhere). The signing script and its configuration live OUTSIDE every  │
 * │ repository; this script only CALLS the one it is given (`--signer`,     │
 * │ `-Targets <file>`) and nothing here knows how to sign. The ORDER is     │
 * │ the one of Obliwan and of the agents of the suite:                      │
 * │   1. exe built (SEA, GUI subsystem, proven by --version / --self-test)  │
 * │   2. exe SIGNED, then VERIFIED here (Authenticode Valid AND the          │
 * │      certificate pinned in src/pins.ts — the signer exits 0 on a target │
 * │      it cannot find, so its exit code proves nothing)                    │
 * │   3. wix build of the MSI, which embeds the SIGNED exe                  │
 * │   4. MSI SIGNED, then VERIFIED                                           │
 * │ Any failure ABORTS and deletes what was built: an unsigned station must │
 * │ never reach a technician's PC (it holds the means to enroll devices).   │
 * │ Without `--release`, the output is a development build, unsigned, and   │
 * │ says so; the station refuses to self-update from an unsigned exe.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE AGENT'S SIGNER IS READ, NEVER WRITTEN ──────────────────────────────┐
 * │ `__AGENT_SIGNER_SHA256__` (src/pins.ts) comes from                       │
 * │ OBLIGARTH_BENCH_AGENT_SIGNER, else from agent-android/local.properties   │
 * │ (`obligarth.agent.pinnedSigners`, the value the agent's release pins,    │
 * │ the certificate of obligarth-agent.jks). A production build without     │
 * │ exactly one such fingerprint REFUSES to build.                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Shared code (shared/src/mdm/bench.ts, server/src/legacyAgent/apkSigner.ts) is bundled by relative path; no module
 * with a database or a logger may enter the bundle: the plugin below fails the build if one does.
 */

import { build } from 'esbuild';
import { execFileSync, execSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readSubsystem, setSubsystem, SUBSYSTEM_CUI, SUBSYSTEM_GUI } from './peSubsystem.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');
const SEA_FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const EXE = 'obligarth-bench.exe';
const MSI = 'obligarth-bench.msi';

const args = process.argv.slice(2);
const has = (flag) => args.includes(flag);
function argValue(flag) {
  const i = args.indexOf(flag);
  if (i === -1) return undefined;
  const v = args[i + 1];
  if (!v || v.startsWith('--')) { console.error(`  ${flag} needs a value`); process.exit(2); }
  return v;
}
/**
 * A tool of the PATH (npx, wix). Under Windows it is a .cmd shim that only cmd.exe runs: ONE command line, each
 * argument between double quotes, so that a path with a space works (an array with shell:true would be joined without
 * quotes, and is deprecated: DEP0190). A character cmd.exe would still read inside quotes is refused.
 */
function runTool(cmd, args, opts) {
  if (process.platform !== 'win32') return execFileSync(cmd, args, opts);
  for (const a of args) if (/["%!^\r\n]/.test(a)) refuse(`${cmd}: an argument holds a character cmd.exe interprets: ${a}`);
  return execSync([cmd, ...args.map((a) => `"${a}"`)].join(' '), { ...opts, shell: process.env.ComSpec || 'cmd.exe' });
}

function refuse(why, cleanup = []) {
  console.error(`\n  REFUSED: ${why}`);
  for (const p of cleanup) rmSync(p, { recursive: true, force: true });
  if (cleanup.length) console.error('  What was built has been deleted: nothing is published.');
  console.error('');
  process.exit(1);
}

function seaInjectionProblem(exeBytes, blobBytes) {
  const fuse = Buffer.from(SEA_FUSE, 'latin1');
  const at = exeBytes.indexOf(fuse);
  if (at === -1) return 'no SEA sentinel fuse in this binary';
  if (exeBytes.indexOf(fuse, at + 1) !== -1) return 'the SEA sentinel fuse appears more than once';
  const state = exeBytes.subarray(at + fuse.length, at + fuse.length + 2).toString('latin1');
  if (state !== ':1') return `the SEA fuse still reads "${state}": the bare Node runtime`;
  if (blobBytes && exeBytes.indexOf(blobBytes) === -1) return "the fuse is flipped but this build's blob is not inside";
  return null;
}

const checkTarget = argValue('--check-sea');
if (checkTarget !== undefined) {
  const blobArg = argValue('--blob');
  const problem = seaInjectionProblem(readFileSync(checkTarget), blobArg ? readFileSync(blobArg) : null);
  console.log(problem ? `NOT an injected SEA: ${problem}` : 'injected SEA: fuse flipped' + (blobArg ? ', blob present' : ''));
  process.exit(problem ? 1 : 0);
}

const version = readFileSync(join(here, 'VERSION'), 'utf8').trim();
if (!/^\d+\.\d+\.\d+$/.test(version)) refuse(`VERSION "${version}" is not x.y.z`);
const dev = has('--dev');
const release = has('--release');
const bundleOnly = has('--bundle-only');
if (dev && release) refuse('--dev and --release exclude each other');

// ── the agent's signer ───────────────────────────────────────────────────────
function agentSigner() {
  const fromEnv = (process.env.OBLIGARTH_BENCH_AGENT_SIGNER ?? '').trim();
  let raw = fromEnv;
  if (!raw) {
    try {
      const props = readFileSync(join(repoRoot, 'agent-android', 'local.properties'), 'utf8');
      const m = /^obligarth\.agent\.pinnedSigners\s*=\s*(.*)$/m.exec(props);
      raw = m ? m[1].trim() : '';
    } catch { raw = ''; }
  }
  const list = raw.split(',').map((s) => s.trim().toLowerCase().replace(/:/g, '')).filter(Boolean);
  if (list.length !== 1 || !/^[0-9a-f]{64}$/.test(list[0])) return null;
  return list[0];
}
const signer = agentSigner();
if (!signer && !dev && !bundleOnly) refuse('no agent signer: set OBLIGARTH_BENCH_AGENT_SIGNER or obligarth.agent.pinnedSigners (exactly one SHA-256) in agent-android/local.properties');

// ── output folder ────────────────────────────────────────────────────────────
const outArg = argValue('--out');
const dist = outArg ? resolve(outArg) : bundleOnly ? mkdtempSync(join(tmpdir(), 'obligarth-bench-bundle-')) : null;
if (!dist) refuse('--out <empty directory> is required (a named directory is never wiped by this script)');
if (existsSync(dist) && readdirSync(dist).length > 0) refuse(`${dist} is not empty. Empty it (or name a new directory) and retry.`);
mkdirSync(dist, { recursive: true });
const bundle = join(dist, 'bench.cjs');
const blob = join(dist, 'bench.blob');
const exe = join(dist, EXE);
console.log(`obligarth-bench v${version}${dev ? ' (development)' : ''}${release ? ' (release)' : ''}  ->  ${dist}`);

// ── 1. bundle ────────────────────────────────────────────────────────────────
console.log('[1] bundling…');
const FORBIDDEN = /(^|[\\/])(db|knex|pg|pino|logger|config)([\\/]index)?(\.ts)?$|^(knex|pg|pino|pino-pretty|express|zod)$/;
await build({
  entryPoints: [join(here, 'src', 'main.ts')],
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'cjs',
  define: {
    __BENCH_VERSION__: JSON.stringify(version),
    __BENCH_DEV__: JSON.stringify(dev),
    __AGENT_SIGNER_SHA256__: JSON.stringify(signer ?? ''),
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  outfile: bundle,
  external: [],
  plugins: [{
    name: 'no-server-runtime-in-the-station',
    setup(b) {
      b.onResolve({ filter: /.*/ }, (a) => {
        const fromServer = /[\\/]server[\\/]src[\\/]/.test(a.importer);
        const isOwnConfig = /[\\/]bench-station[\\/]src[\\/]/.test(a.importer) && a.path === './config';
        if (!isOwnConfig && (fromServer || /^(knex|pg|pino|pino-pretty|express|zod)$/.test(a.path)) && FORBIDDEN.test(a.path)) {
          return { errors: [{ text: `the station must not bundle "${a.path}" (imported by ${a.importer}): no database, no logger, no server runtime` }] };
        }
        return null;
      });
    },
  }],
  minify: false,
  sourcemap: false,
  logLevel: 'warning',
}).catch(() => refuse('the bundle failed (see above)', bundleOnly ? [dist] : []));
const bundleSha = createHash('sha256').update(readFileSync(bundle)).digest('hex');
console.log(`  bundle: ${bundle} (${readFileSync(bundle).length} bytes, sha256 ${bundleSha.slice(0, 16)}…)`);
if (bundleOnly) {
  console.log('  --bundle-only: no executable is built.');
  process.exit(0);
}

// ── 2. SEA ───────────────────────────────────────────────────────────────────
console.log('[2] sea-config…');
const seaConfig = join(dist, 'sea-config.json');
writeFileSync(seaConfig, JSON.stringify({ main: bundle, output: blob, disableExperimentalSEAWarning: true, useSnapshot: false, useCodeCache: true }, null, 2));
execFileSync(process.execPath, ['--experimental-sea-config', seaConfig], { stdio: 'inherit' });

/**
 * signtool.exe, to remove node.exe's own signature (rcedit and the injection would leave it corrupted, and no signer
 * signs over a corrupted one): OBLIGARTH_BENCH_SIGNTOOL, else a Windows SDK, else the kit that travels with the
 * signing script (`<its folder>\lfsign\kits\bin\<version>\x64`, then `<its folder>\lfsign\signtool`).
 */
function findSigntool() {
  const forced = (process.env.OBLIGARTH_BENCH_SIGNTOOL ?? '').trim();
  if (forced) return existsSync(forced) ? forced : null;
  const roots = ['C:\\Program Files (x86)\\Windows Kits\\10\\bin', 'C:\\Program Files\\Windows Kits\\10\\bin'];
  const signerArg = args.includes('--signer') ? args[args.indexOf('--signer') + 1] : undefined;
  if (signerArg && !signerArg.startsWith('--')) roots.push(join(dirname(resolve(signerArg)), 'lfsign', 'kits', 'bin'));
  const found = [];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const ver of readdirSync(root)) {
      for (const arch of ['x64', 'x86']) {
        const p = join(root, ver, arch, 'signtool.exe');
        if (existsSync(p)) found.push({ p, arch, ver });
      }
    }
  }
  if (found.length === 0 && signerArg && !signerArg.startsWith('--')) {
    const beside = join(dirname(resolve(signerArg)), 'lfsign', 'signtool', 'signtool.exe');
    if (existsSync(beside)) return beside;
  }
  if (found.length === 0) return null;
  found.sort((a, b) => (a.arch === b.arch ? b.ver.localeCompare(a.ver) : a.arch === 'x64' ? -1 : 1));
  return found[0].p;
}

console.log('[3] copying the node runtime, removing its signature…');
copyFileSync(process.execPath, exe);
if (process.platform === 'win32') {
  const signtool = findSigntool();
  // A release is signed: with node.exe's signature still inside, the signer refuses the file (0x800700C1).
  if (!signtool && release) refuse('signtool.exe not found (Windows SDK, OBLIGARTH_BENCH_SIGNTOOL, or the kit beside the signing script): node.exe\'s own signature cannot be removed, and the signing would fail', [dist]);
  if (!signtool) console.log('  ! signtool.exe not found: the signature of node.exe is not removed (signing may then fail)');
  else { try { execFileSync(signtool, ['remove', '/s', exe], { stdio: 'pipe' }); console.log("  node's own signature removed"); } catch { console.log('  (no signature to remove)'); } }
}

// The icon of Obligarth and the version information of the station, written into the copy of node.exe BEFORE the
// injection (the blob is a resource added after, which rcedit would otherwise have to carry) and before any signing,
// so that the signature covers them. Only on Windows: the resources are a PE matter, and rcedit is a Windows tool.
if (process.platform === 'win32') {
  console.log('    icon and version information…');
  const { default: rcedit } = await import('rcedit');
  const winVersion = `${version}.0`;
  try {
    await rcedit(exe, {
      icon: join(here, 'installer', 'obligarth-bench.ico'),
      'file-version': winVersion,
      'product-version': winVersion,
      'version-string': {
        ProductName: 'Obligarth Bench',
        FileDescription: 'Obligarth Bench',
        CompanyName: 'Obli tools',
        LegalCopyright: 'Obli tools',
        OriginalFilename: EXE,
        InternalName: 'obligarth-bench',
      },
    });
  } catch (err) {
    refuse(`icon and version information: ${err.message}`, [exe]);
  }
}

console.log('[4] injecting…');
try {
  runTool('npx', ['--yes', 'postject@1.0.0-alpha.6', exe, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', SEA_FUSE], { stdio: 'inherit' });
} catch (err) {
  refuse(`injection failed: ${err.message}`, [exe]);
}
const injectionProblem = seaInjectionProblem(readFileSync(exe), readFileSync(blob));
if (injectionProblem) refuse(`the injection did not take — ${injectionProblem}`, [exe]);

console.log('[5] Windows GUI subsystem, proven on a copy…');
{
  const guiCopy = join(dist, 'obligarth-bench.gui-check.exe');
  const proof = join(dist, 'gui-self-test.txt');
  const bytes = readFileSync(exe);
  const before = setSubsystem(bytes, SUBSYSTEM_GUI);
  if (before !== SUBSYSTEM_CUI && before !== SUBSYSTEM_GUI) refuse(`unexpected subsystem ${before}`, [exe]);
  writeFileSync(guiCopy, bytes);
  if (readSubsystem(readFileSync(guiCopy)) !== SUBSYSTEM_GUI) refuse('the subsystem did not read back as GUI', [exe, guiCopy]);
  if (process.platform === 'win32') {
    let printed = '';
    try { printed = execFileSync(guiCopy, ['--version'], { encoding: 'utf8', timeout: 60_000, windowsHide: true }).trim(); } catch (err) { refuse(`--version failed: ${err.message}`, [exe, guiCopy]); }
    if (printed !== version) refuse(`--version printed "${printed.slice(0, 60)}", expected "${version}"`, [exe, guiCopy]);
    try {
      execFileSync('cmd', ['/d', '/s', '/c', `"start "" /wait "${guiCopy}" --self-test "${proof}""`], { timeout: 60_000, windowsHide: true, stdio: 'ignore', windowsVerbatimArguments: true });
    } catch (err) { refuse(`--self-test failed: ${err.message}`, [exe, guiCopy]); }
    const said = existsSync(proof) ? readFileSync(proof, 'utf8').trim() : '';
    rmSync(proof, { force: true });
    if (said !== `ok ${version}`) refuse(`--self-test wrote "${said.slice(0, 60)}" with no console attached`, [exe, guiCopy]);
  }
  rmSync(exe, { force: true });
  renameSync(guiCopy, exe);
}
for (const f of [bundle, blob, seaConfig]) rmSync(f, { force: true });

const wxs = join(dist, 'product.wxs');
writeFileSync(wxs, readFileSync(join(here, 'installer', 'product.wxs'), 'utf8').replace('BENCH_VERSION_PLACEHOLDER', version));
copyFileSync(join(here, 'installer', 'obligarth-bench.ico'), join(dist, 'obligarth-bench.ico'));
writeFileSync(join(dist, 'VERSION'), `${version}\n`);

if (!release) {
  writeFileSync(join(dist, 'UNSIGNED.txt'), 'Development build of the Obligarth bench station: NOT SIGNED, never to be installed on a technician\'s PC.\n');
  console.log(`\n  built: ${exe}  (v${version})  — NOT SIGNED (no --release).\n`);
  process.exit(0);
}

// ── 6. signing (outside the repository), verified here ──────────────────────
const signerScript = argValue('--signer');
if (!signerScript || !existsSync(signerScript)) refuse('--release needs --signer <the signing script, outside the repository>', [dist]);

/** The pinned code-signing certificates of src/pins.ts, read as text (one source of truth). */
function pinnedCertificates() {
  const text = readFileSync(join(here, 'src', 'pins.ts'), 'utf8');
  const pins = [];
  for (const m of text.matchAll(/issuer:\s*'([^']+)',\s*\n?\s*sha256:\s*'([0-9A-F]{64})'/g)) pins.push({ issuer: m[1], sha256: m[2] });
  return pins;
}
const pins = pinnedCertificates();
if (pins.length === 0) refuse('no code-signing certificate is pinned in src/pins.ts', [dist]);

function sign(file) {
  try {
    execFileSync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', signerScript, '-Targets', file], { stdio: 'inherit', windowsHide: true, timeout: 600_000 });
  } catch (err) {
    refuse(`signing ${file} failed: ${err.message}`, [dist]);
  }
}
function verify(file) {
  let out = '';
  try {
    out = execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      "$s = Get-AuthenticodeSignature -LiteralPath $env:OBLIGARTH_SIG_FILE; $c = $s.SignerCertificate; if ($c -eq $null) { '' + $s.Status + '||' } else { '' + $s.Status + '|' + $c.Issuer + '|' + $c.GetCertHashString('SHA256') }"],
    { encoding: 'utf8', windowsHide: true, timeout: 60_000, env: { ...process.env, OBLIGARTH_SIG_FILE: file } }).trim();
  } catch (err) {
    refuse(`the signature of ${file} could not be read: ${err.message}`, [dist]);
  }
  const [status, issuer, sha] = out.split('|');
  if (status !== 'Valid') refuse(`${file}: signature ${status || 'absent'} (the signer's exit code proves nothing)`, [dist]);
  if (!pins.some((p) => p.issuer === issuer && p.sha256 === (sha ?? '').toUpperCase())) refuse(`${file}: signed by a certificate that is not pinned in src/pins.ts`, [dist]);
  console.log(`  ${file}: signature Valid, pinned certificate`);
}

console.log('[6] signing the exe…');
sign(exe);
verify(exe);
console.log('[7] building the MSI (WiX v4)…');
try {
  runTool('wix', ['build', wxs, '-b', dist, '-arch', 'x64', '-out', join(dist, MSI)], { stdio: 'inherit' });
} catch (err) {
  refuse(`wix build failed: ${err.message}`, [dist]);
}
console.log('[8] signing the MSI…');
sign(join(dist, MSI));
verify(join(dist, MSI));
const msiSha = createHash('sha256').update(readFileSync(join(dist, MSI))).digest('hex');
writeFileSync(join(dist, 'SHA256SUMS'), `${msiSha}  ${MSI}\n${createHash('sha256').update(readFileSync(exe)).digest('hex')}  ${EXE}\n`);
console.log(`\n  built and signed: ${join(dist, MSI)}  (v${version}, sha256 ${msiSha})\n`);
