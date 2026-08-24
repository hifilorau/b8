-- Up Migration

-- A Plaid Item — one institution connection — is the unit that owns an access_token and a
-- transactionsSync cursor, and the unit that fails and gets re-authenticated. Until now it
-- had no row: the token and cursor were copied onto EVERY account behind the connection, and
-- the Item was reconstructed at runtime by grouping on the token string (lib/sync.ts's
-- byToken map, SyncHealthCard's GROUP BY access_token, plaidReconcile's WHERE access_token =
-- $1). Two things follow from that, and both are fixed here.
--
-- 1. The cursor invariant was maintained only by convention. lib/sync.ts read an Item's
--    cursor from whichever account row came back first — there is no ORDER BY — and wrote the
--    new one to all of them. Siblings CAN diverge: the dup-merge branch in exchange-token
--    sets one row's cursor to NULL while the plain-reconnect branch conditionally preserves
--    others'. Picking a sibling whose cursor is further ahead than the Item's true position
--    makes transactionsSync skip those transactions permanently — the one sync failure the
--    ON CONFLICT upsert cannot repair, because the rows never arrive at all. One cursor per
--    Item makes that state unrepresentable rather than merely unlikely.
--
-- 2. The token was the join key, so it could not be encrypted. Every lookup above compares it
--    by value, and randomized-IV ciphertext compares unequal to itself. Encrypting first
--    would have forced deterministic encryption purely to keep `=` working — a crypto
--    compromise driven by a schema defect. A surrogate integer key removes the reason.
--
-- Deliberately additive: accounts.access_token and accounts.cursor stay for now, so this
-- migration's down is lossless and the call-site rewrite is a separate reviewable change.
-- They are dropped in a later migration once nothing reads them.
CREATE TABLE plaid_items (
  id             SERIAL PRIMARY KEY,
  -- Plaid's own item_id. Nullable because existing connections were linked before we stored
  -- it (exchange-token called itemGet only for institution_id and discarded the rest); it is
  -- backfilled on the next re-link. UNIQUE so the reconnect path can upsert on it.
  item_id        TEXT UNIQUE,
  -- Nullable: the demo seed creates Items with no credential, and an Item whose accounts have
  -- all been unlinked has nothing to hold. Not UNIQUE — this column becomes ciphertext later,
  -- where uniqueness would constrain the IV rather than the token.
  access_token   TEXT,
  cursor         TEXT,
  institution_id TEXT,
  bank           TEXT,
  last_synced_at TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ON DELETE SET NULL, not CASCADE: an account carries transaction history, manual valuations
-- and hand-assigned categories that exist nowhere else, so unlinking a connection must not
-- delete them. A null plaid_item_id is exactly what the app already reads as "manual".
ALTER TABLE accounts ADD COLUMN plaid_item_id INT REFERENCES plaid_items(id) ON DELETE SET NULL;

INSERT INTO plaid_items (access_token, cursor, bank, last_synced_at)
SELECT access_token,
       -- Collapsing N sibling cursors into one is the only lossy step here, so it errs
       -- deliberately toward NULL. A NULL cursor means "full backfill on the next sync",
       -- which is SAFE: transactions dedupe on the plaid_transaction_id upsert, so the worst
       -- case is one slow sync. Any other choice risks adopting a cursor that is further
       -- ahead than the Item's true position, which skips transactions with no way to notice.
       -- So: keep the cursor only when every sibling agrees and none is NULL.
       CASE WHEN bool_or(cursor IS NULL) OR COUNT(DISTINCT cursor) > 1
            THEN NULL
            ELSE MIN(cursor) END,
       MIN(bank),
       -- The success marker behind the staleness model (lib/domain/syncHealth.ts). MAX is the
       -- Item's real last success: siblings are written together, so they agree, and taking
       -- the newest cannot make a broken connection look healthier than its best row already did.
       MAX(last_synced_at)
  FROM accounts
 WHERE access_token IS NOT NULL
 GROUP BY access_token;

UPDATE accounts a
   SET plaid_item_id = i.id
  FROM plaid_items i
 WHERE i.access_token = a.access_token;

-- Every per-Item query joins through this; without it they are sequential scans of accounts.
CREATE INDEX idx_accounts_plaid_item_id ON accounts(plaid_item_id);

-- Down Migration

-- Lossless: accounts.access_token and accounts.cursor were never removed, so dropping the
-- new table and column returns the schema to exactly its previous shape with no data gone.
DROP INDEX IF EXISTS idx_accounts_plaid_item_id;
ALTER TABLE accounts DROP COLUMN IF EXISTS plaid_item_id;
DROP TABLE IF EXISTS plaid_items;
