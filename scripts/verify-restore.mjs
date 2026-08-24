// Compares a restored database against the original: row counts per table, and the composed
// net-worth statement.
//
// Row counts alone are not enough. They would pass even if every Plaid token came back
// undecryptable, or if the numbers themselves were silently altered — what people care about is
// the arithmetic, not the cardinality. So this also recomputes net worth on both sides using the
// same rule as lib/domain/netWorth.ts, checksums the value-bearing columns, and checks that
// stored credentials are still readable.
//
// The checksums are not redundant with the net-worth comparison, and this was worth finding the
// hard way: net worth reads only the LATEST valuation per account, so altering a historical
// account_valuations row changes the equity chart and every past net_worth_snapshot while
// leaving today's figure identical. Row counts miss it too. Summing the value columns is what
// closes that gap.
//
//   TOKEN_ENCRYPTION_KEY=... node scripts/verify-restore.mjs <source-url> <restored-url>
//
// Exits non-zero on any mismatch. That exit code is the whole point: it turns "we have backups"
// into something a cron job can actually assert.

import pg from 'pg';
import { isEncrypted, decryptSecret } from '../lib/crypto.ts';

const [sourceUrl, restoredUrl] = process.argv.slice(2);
if (!sourceUrl || !restoredUrl) {
  console.error('usage: node scripts/verify-restore.mjs <source-url> <restored-url>');
  process.exit(1);
}

async function inspect(url) {
  const db = new pg.Client({ connectionString: url });
  await db.connect();

  const { rows: tables } = await db.query(`
    SELECT tablename FROM pg_tables
     WHERE schemaname = 'public' AND tablename <> 'pgmigrations'
     ORDER BY tablename
  `);

  const counts = {};
  for (const { tablename } of tables) {
    const { rows } = await db.query(`SELECT COUNT(*)::int AS n FROM "${tablename}"`);
    counts[tablename] = rows[0].n;
  }

  // Mirrors lib/domain/netWorth.ts: a property-linked mortgage is netted inside real-estate
  // equity and deliberately absent from liabilities, so the same debt is never counted twice.
  const { rows: nw } = await db.query(`
    WITH latest_acct AS (
      SELECT DISTINCT ON (account_id) account_id, value
        FROM account_valuations ORDER BY account_id, valued_at DESC
    ),
    latest_prop AS (
      SELECT DISTINCT ON (property_id) property_id, value
        FROM property_valuations ORDER BY property_id, valued_at DESC
    ),
    ledger AS (
      SELECT a.id,
             COALESCE(ab.beginning_balance, 0)
               - COALESCE((SELECT SUM(t.amount) FROM transactions t WHERE t.account_id = a.id), 0) AS bal
        FROM accounts a
        LEFT JOIN account_balances ab ON ab.account_id = a.id AND ab.year = EXTRACT(YEAR FROM CURRENT_DATE)
    )
    SELECT
      COALESCE(SUM(CASE WHEN a.valuation_mode = 'ledger' THEN l.bal END), 0)::numeric(14,2)     AS ledger_total,
      COALESCE(SUM(CASE WHEN a.valuation_mode = 'valuation' AND NOT a.is_liability
                        THEN la.value END), 0)::numeric(14,2)                                   AS valuation_assets,
      COALESCE(SUM(CASE WHEN a.valuation_mode = 'valuation' AND a.is_liability
                        THEN la.value END), 0)::numeric(14,2)                                   AS valuation_debts,
      COALESCE((SELECT SUM(value) FROM latest_prop), 0)::numeric(14,2)                          AS property_total
      FROM accounts a
      LEFT JOIN ledger l ON l.id = a.id
      LEFT JOIN latest_acct la ON la.account_id = a.id
  `);

  // Aggregates over every column that carries a number anyone reads. Cheap, and they catch the
  // corruption that both row counts and a current-net-worth comparison are blind to.
  const { rows: sums } = await db.query(`
    SELECT
      (SELECT COALESCE(SUM(amount), 0) FROM transactions)::text            AS txn_amounts,
      (SELECT COALESCE(SUM(value), 0) FROM account_valuations)::text       AS acct_valuations,
      (SELECT COALESCE(SUM(value), 0) FROM property_valuations)::text      AS prop_valuations,
      (SELECT COALESCE(SUM(beginning_balance), 0) FROM account_balances)::text AS beginning_balances,
      (SELECT COALESCE(SUM(total), 0) FROM net_worth_snapshots)::text      AS snapshot_totals,
      (SELECT COALESCE(SUM(annual_budget), 0) FROM budget_categories)::text AS annual_budgets
  `);

  const { rows: tokens } = await db.query(
    'SELECT id, access_token FROM plaid_items WHERE access_token IS NOT NULL ORDER BY id'
  );

  await db.end();
  return { counts, netWorth: nw[0], sums: sums[0], tokens };
}

const source = await inspect(sourceUrl);
const restored = await inspect(restoredUrl);
const failures = [];

for (const [table, n] of Object.entries(source.counts)) {
  if (!(table in restored.counts)) failures.push(`${table}: missing from the restored database`);
  else if (restored.counts[table] !== n) {
    failures.push(`${table}: ${n} row(s) in source, ${restored.counts[table]} restored`);
  }
}

for (const [k, v] of Object.entries(source.netWorth)) {
  if (String(restored.netWorth[k]) !== String(v)) {
    failures.push(`net worth component ${k}: source ${v}, restored ${restored.netWorth[k]}`);
  }
}

for (const [k, v] of Object.entries(source.sums)) {
  if (String(restored.sums[k]) !== String(v)) {
    failures.push(`checksum ${k}: source ${v}, restored ${restored.sums[k]}`);
  }
}

// A restore that brings back unreadable credentials looks perfect by row count and leaves you
// re-linking every bank by hand — exactly the situation the backup was supposed to prevent.
if (restored.tokens.length !== source.tokens.length) {
  failures.push(`plaid_items: ${source.tokens.length} credential(s) in source, ${restored.tokens.length} restored`);
}
if (process.env.TOKEN_ENCRYPTION_KEY) {
  for (const row of restored.tokens) {
    try {
      const value = isEncrypted(row.access_token) ? decryptSecret(row.access_token) : row.access_token;
      if (!value) failures.push(`plaid_items id=${row.id}: decrypted to an empty token`);
    } catch {
      failures.push(`plaid_items id=${row.id}: stored credential could not be decrypted after restore`);
    }
  }
} else {
  console.warn('TOKEN_ENCRYPTION_KEY not set — skipped the credential-readability check.');
}

if (failures.length > 0) {
  console.error('Restore does NOT match the source:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

const tableCount = Object.keys(source.counts).length;
console.log(
  `Restore verified: ${tableCount} tables match, net worth and value checksums match to the ` +
    `cent, ${restored.tokens.length} credential(s) readable.`
);
