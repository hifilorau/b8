-- Up Migration

-- accounts.access_token and accounts.cursor are now dead weight: since the plaid_items
-- migration nothing reads them, and lib/plaidItems.ts is the only place a token is selected.
-- Keeping a second copy of a live bank credential on every account row is exactly the blast
-- radius the encryption work exists to shrink, so it goes before that lands rather than after.
--
-- Deliberately a separate migration from the one that added plaid_items: that one was purely
-- additive and fully reversible, and pairing an irreversible drop with it would have meant
-- neither could be reviewed or rolled back on its own.
ALTER TABLE accounts
  DROP COLUMN IF EXISTS access_token,
  DROP COLUMN IF EXISTS cursor;

-- Down Migration

-- Genuinely lossless, which a column drop usually is not. The values were not deleted, they
-- were moved: plaid_items still holds the token and cursor for every connection, so the down
-- re-derives what each account carried instead of re-adding the columns as NULL.
--
-- That distinction matters more than it looks. A down migration that restores the SHAPE but
-- not the DATA passes an empty-database up/down/up in CI while destroying a real database on
-- a real rollback — the exact trap scripts/db-snapshot.mjs was written to catch.
--
-- The cursor is restored per Item, so every account behind one connection gets the same value.
-- That is the invariant the old schema only maintained by convention, and re-establishing it
-- here means a rollback lands in a consistent state rather than the divergent one that made
-- this refactor necessary.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS access_token TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS cursor TEXT;

UPDATE accounts a
   SET access_token = i.access_token,
       cursor       = i.cursor
  FROM plaid_items i
 WHERE i.id = a.plaid_item_id;
