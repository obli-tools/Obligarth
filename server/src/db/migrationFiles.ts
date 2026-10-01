import { readdirSync } from 'node:fs';
import path from 'node:path';
import { MIGRATIONS } from '../../knexfile';

/** The migration files this image ships, sorted (what Knex would load). */
export function shippedMigrations(): string[] {
  const dir = String(MIGRATIONS.directory);
  const exts = MIGRATIONS.loadExtensions ?? ['.js'];
  return readdirSync(dir)
    .filter((f) => exts.includes(path.extname(f)) && !f.endsWith('.d.ts'))
    .sort();
}

/** A migration's name without its extension: the same migration applied
 *  from the compiled image (.js) or under tsx (.ts). */
export function migrationStem(name: string): string {
  return name.replace(/\.(ts|js|cjs|mjs)$/, '');
}

/** The shipped migrations missing from `applied` (names of the tracking
 *  table), compared without extension. */
export function missingMigrations(applied: ReadonlyArray<string>): string[] {
  const done = new Set(applied.map(migrationStem));
  return shippedMigrations().filter((f) => !done.has(migrationStem(f)));
}
