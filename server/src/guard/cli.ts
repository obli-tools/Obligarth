// Commands of the guard engine (docs: audit-durci §7.5), in the server's image:
//   node dist/src/guard/cli.js restore-reconcile     (image: docker compose run --rm server …)
//   npx tsx src/guard/cli.ts restore-reconcile       (development)
//
//   restore-reconcile
//       after a restore, the server in JOBS_MODE=paused, before the journal's
//       own restore-reconcile: every guarded action awaiting approval,
//       scheduled or executing is paused (guard.action_paused, motif
//       'restore') and every pending approval request expires. No destructive
//       action prior to the restore runs without being confirmed again
//       (conception §5.9, R24). JSON report on the output. Exit 0, 1.
// Runs as the server does (runtime role, DATABASE_URL, signed contexts with
// RLS_CONTEXT_KEY_FILE: rls-tenant §4.6), in the database context of its job
// actor (j:actions.restore-reconcile). A context the database does not accept
// would hide every row and pause nothing: the command checks its context
// first and stops (exit 1) when the database refuses it.
import '../env';

function out(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, process.stdout.isTTY ? 2 : undefined)}\n`);
}

const ACTOR = { type: 'job' as const, name: 'actions.restore-reconcile' };

async function restoreReconcile(): Promise<number> {
  const { db } = await import('../db');
  const { asTenant, configureContextSigningFromFile } = await import('../db/context');
  const { config } = await import('../config');
  const { registerAuditModule } = await import('../audit/module');
  const { registerGuardModule } = await import('./module');
  const { restoreReconcile: run } = await import('./executor');
  try {
    configureContextSigningFromFile(config.rlsContextKeyFile);
    // Self-test of the database context (as the server's boot guard does).
    const probe = await asTenant(1, ACTOR, () => db.raw('SELECT obligarth.ctx_tenant() AS t')) as { rows: Array<{ t: number | null }> };
    if (Number(probe.rows[0]?.t) !== 1) {
      process.stderr.write('restore-reconcile: the database refused the context of this command '
        + '(set RLS_CONTEXT_KEY_FILE to the key of the server): nothing was done\n');
      return 1;
    }
    registerAuditModule();
    registerGuardModule();
    const report = await run(ACTOR, `restore-${new Date().toISOString()}`);
    out(report);
  } finally {
    await db.destroy().catch(() => undefined);
  }
  return 0;
}

const COMMANDS: Record<string, () => Promise<number>> = {
  'restore-reconcile': restoreReconcile,
};

async function main(): Promise<number> {
  const [command] = process.argv.slice(2);
  const run = command ? COMMANDS[command] : undefined;
  if (!run) {
    process.stderr.write(`usage: guard <${Object.keys(COMMANDS).join(' | ')}>\n`);
    return 1;
  }
  return run();
}

if (require.main === module) {
  main().then((code) => { process.exitCode = code; }, (err) => {
    process.stderr.write(`${(err as Error)?.message ?? String(err)}\n`);
    process.exitCode = 1;
  });
}

export const guardCli = { restoreReconcile };
