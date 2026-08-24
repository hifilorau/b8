-- Up Migration

-- The re-identification lookup in lib/sync.ts runs on every page of every sync:
--
--   SELECT ... FROM transactions WHERE account_id = ANY($1) AND date BETWEEN $2 AND $3
--
-- and had no supporting index — only idx_transactions_date, which cannot serve the
-- account_id half of that predicate, so it degraded to a scan of the whole table as history
-- accumulated. The column order matters: account_id is an equality (ANY) test and date is a
-- range test, so account_id must lead for the range to be satisfied by the index rather than
-- as a filter afterwards.
--
-- This also serves the per-account reads that lib/drift.ts and lib/netWorth.ts issue when
-- summing a ledger account's running balance.
CREATE INDEX IF NOT EXISTS idx_transactions_account_id_date ON transactions(account_id, date);

-- Down Migration

DROP INDEX IF EXISTS idx_transactions_account_id_date;
