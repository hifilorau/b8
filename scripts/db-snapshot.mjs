// Row-count snapshot / comparison, used by CI to prove a migration round trip preserves data.
//
// Why this exists: CI already ran `migrate:up → down → up`, but against an EMPTY database.
// That proves the DDL is reversible and says nothing at all about whether data survives —
// and the migrations coming next (extracting plaid_items, dropping the legacy token columns,
// encrypting tokens) are all backfills over existing rows. A down-migration that re-adds a
// column as NULL passes an empty-database round trip green and destroys real data on a real
// rollback. Seeding first and diffing row counts is what closes that gap.
//
// Usage:
//   node scripts/db-snapshot.mjs write   <path>                   # capture counts to a file
//   node scripts/db-snapshot.mjs compare <before> <rolled-back>   # re-capture and diff
//
// `compare` takes two snapshots because a down migration legitimately drops the tables that
// its own up migration created, and the re-up then recreates them empty. Naively diffing
// before-vs-after flags that as data loss. The second snapshot — taken while rolled back —
// is what tells the two cases apart: a table absent there was created by the migration under
// test, so its emptiness afterwards is correct. A table that survived the rollback and still
// lost rows is a real failure. The intended sequence is:
//
//   migrate:up && seed:demo
//   db-snapshot write before.json
//   migrate:down
//   db-snapshot write rolled-back.json
//   migrate:up
//   db-snapshot compare before.json rolled-back.json
//
// Reads DATABASE_URL from the environment. Prints counts only — never row contents — so it
// is safe to run against a real database and safe to paste into a CI log.

import pg from 'pg';
import { readFileSync, writeFileSync } from 'node:fs';

// Tables that must survive ANY single-migration rollback. A migration is free to add and
// drop its own new tables — that is what a down migration is for — but if one of these
// disappears or empties out, a real rollback would be a data-loss event and CI should say so
// before it reaches a production database.
const CRITICAL_TABLES = [
  'accounts',
  'transactions',
  'properties',
  'property_valuations',
  'account_valuations',
  'account_balances',
  'budget_categories',
];

const [mode, path, rolledBackPath] = process.argv.slice(2);

if (mode !== 'write' && mode !== 'compare') {
  console.error('usage: node scripts/db-snapshot.mjs <write|compare> <path> [rolled-back-path]');
  process.exit(1);
}
if (!path || (mode === 'compare' && !rolledBackPath)) {
  console.error('usage: node scripts/db-snapshot.mjs <write|compare> <path> [rolled-back-path]');
  process.exit(1);
}

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
await client.connect();

// Every ordinary table in the public schema, minus node-pg-migrate's own bookkeeping (whose
// row count legitimately changes on every migration, which is the whole point of it).
const { rows: tables } = await client.query(`
  SELECT tablename
    FROM pg_tables
   WHERE schemaname = 'public' AND tablename <> 'pgmigrations'
   ORDER BY tablename
`);

const counts = {};
for (const { tablename } of tables) {
  // Identifier, not a value, so it cannot be parameterized. The list comes from pg_tables in
  // this database rather than from user input, and is quoted to be safe regardless.
  const { rows } = await client.query(`SELECT COUNT(*)::int AS n FROM "${tablename}"`);
  counts[tablename] = rows[0].n;
}

await client.end();

if (mode === 'write') {
  writeFileSync(path, JSON.stringify(counts, null, 2));
  console.log(`Captured ${Object.keys(counts).length} tables to ${path}`);
  process.exit(0);
}

const before = JSON.parse(readFileSync(path, 'utf8'));
const rolledBack = JSON.parse(readFileSync(rolledBackPath, 'utf8'));
const failures = [];

// Only tables that still existed while rolled back are compared. One that did not is a table
// the migration under test created, so the re-up recreating it empty is correct, not a loss.
for (const [table, beforeCount] of Object.entries(before)) {
  if (!(table in rolledBack)) continue;
  if (!(table in counts)) {
    failures.push(`${table}: survived the rollback but is missing after re-applying`);
  } else if (counts[table] !== beforeCount) {
    failures.push(`${table}: ${beforeCount} row(s) before, ${counts[table]} after`);
  }
}

// The rule above — "a table the migration owns may come back empty" — must never become an
// excuse for losing the ledger. If a down migration drops one of these out from under
// populated data, a real rollback is a data-loss event, and that is precisely the trap an
// empty-database round trip cannot see.
for (const table of CRITICAL_TABLES) {
  if (!(table in counts)) {
    failures.push(`${table}: table no longer exists after the migration round trip`);
  } else if (before[table] > 0 && !(table in rolledBack)) {
    failures.push(
      `${table}: dropped by the down migration while holding ${before[table]} row(s) — ` +
        'a real rollback would lose them'
    );
  }
}

if (failures.length > 0) {
  console.error('Migration round trip did NOT preserve data:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log(`Migration round trip preserved all data (${Object.keys(counts).length} tables checked).`);
