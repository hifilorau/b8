// Asserts the plaid_items backfill collapses sibling cursors safely.
//
// This guards a one-shot migration that runs exactly once against a real household database,
// where getting it wrong is close to unobservable: adopting a cursor further ahead than the
// Item's true position makes transactionsSync skip those transactions permanently, and the
// ON CONFLICT upsert cannot repair rows that never arrive. The safe direction is always NULL
// (a full backfill that dedupes), so the rule is "keep the cursor only when every sibling
// agrees and none is missing" — and this asserts exactly that, on data shaped to hit each case.
//
// Run against a THROWAWAY database: it migrates down to before plaid_items and wipes accounts.
//   DATABASE_URL=... node scripts/test-plaid-items-backfill.mjs

import pg from 'pg';
import { execFileSync } from 'node:child_process';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

const migrate = (...args) =>
  execFileSync('npx', ['node-pg-migrate', ...args], { stdio: 'pipe', env: process.env });

const db = new pg.Client({ connectionString: process.env.DATABASE_URL });
await db.connect();

// Roll back to just before plaid_items, then stage the pre-migration shape.
migrate('down');
await db.query('TRUNCATE accounts RESTART IDENTITY CASCADE');
await db.query(`
  INSERT INTO accounts (id, name, type, access_token, cursor, bank, last_synced_at) VALUES
    ('a1','A One','depository','tok-A','cur-A','Bank A', now() - interval '2 hours'),
    ('a2','A Two','depository','tok-A','cur-A','Bank A', now() - interval '3 hours'),
    ('b1','B One','depository','tok-B','cur-B','Bank B', now() - interval '5 hours'),
    ('b2','B Two','depository','tok-B', NULL,  'Bank B', now() - interval '5 hours'),
    ('c1','C One','depository','tok-C','cur-old','Bank C', now() - interval '9 hours'),
    ('c2','C Two','depository','tok-C','cur-new','Bank C', now() - interval '1 hour'),
    ('m1','Manual','other',     NULL,   NULL,   NULL,     NULL)
`);

migrate('up');

const { rows } = await db.query(`
  SELECT i.access_token AS token, i.cursor, COUNT(a.id)::int AS accounts
    FROM plaid_items i LEFT JOIN accounts a ON a.plaid_item_id = i.id
   GROUP BY i.id, i.access_token, i.cursor ORDER BY i.access_token
`);
const { rows: manual } = await db.query("SELECT plaid_item_id FROM accounts WHERE id = 'm1'");

const failures = [];
const item = (t) => rows.find((r) => r.token === t);
const expect = (label, actual, wanted) => {
  if (actual !== wanted) failures.push(`${label}: expected ${wanted}, got ${actual}`);
};

expect('one Item per distinct token', rows.length, 3);
// Every sibling agrees and none is missing — the only case where keeping it is safe.
expect('agreeing siblings keep their cursor', item('tok-A')?.cursor, 'cur-A');
expect('tok-A groups both accounts', item('tok-A')?.accounts, 2);
// One sibling never synced, so the group has no single known position.
expect('a NULL sibling forces a full backfill', item('tok-B')?.cursor, null);
// The bug this whole table exists to make unrepresentable: never pick a winner.
expect('divergent siblings force a full backfill', item('tok-C')?.cursor, null);
expect('an unlinked account gets no Item', manual[0]?.plaid_item_id, null);

await db.end();

if (failures.length > 0) {
  console.error('plaid_items backfill is unsafe:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log('plaid_items backfill collapses sibling cursors safely (3 Items, 5 assertions).');
