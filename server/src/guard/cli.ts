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
// Runs as the server does (runtime role, DATABASE_URL), in the database
// context of its job actor (j:actions.restore-reconcile).
import '../env';

function out(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, process.stdout.isTTY ? 2 : undefined)}\n`);
}

async function restoreReconcile(): Promise<number> {
  const { db } = await import('../db');
  const { registerAuditModule } = await import('../audit/module');
  const { registerGuardModule } = await import('./module');
  const { restoreReconcile: run } = await import('./executor');
  registerAuditModule();
  registerGuardModule();
  try {
    const report = await run({ type: 'job', name: 'actions.restore-reconcile' }, `restore-${new Date().toISOString()}`);
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
