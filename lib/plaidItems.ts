// The Plaid Item — one institution login — as a first-class row rather than a value grouped
// out of `accounts` at runtime. See migrations/1787572606405_plaid-items.sql for why.
//
// This module is deliberately the ONLY place `plaid_items.access_token` is selected. Every
// caller works in terms of an item id and receives the token as a field it passes straight to
// the Plaid SDK; nothing joins, groups or compares by its value any more. That is what made
// encrypting the column a change confined to this file: it is encrypted on write and decrypted
// on read here, and the call sites that used to key off the token never noticed.
//
// The column holds ciphertext (lib/crypto.ts) but is still plain TEXT, and reads tolerate a
// value that has not been encrypted yet. That is what lets scripts/encrypt-plaid-tokens.mjs
// run against a live database instead of needing the app stopped.

import db from './db';
import { createLogger } from './logger';
import { encryptSecret, decryptSecret, isEncrypted } from './crypto';

const log = createLogger('plaidItems');

/**
 * Accepts a not-yet-encrypted value so the backfill can run while the app is serving. Once
 * scripts/encrypt-plaid-tokens.mjs has been run, every row takes the first branch.
 */
function readToken(stored: string): string {
  return isEncrypted(stored) ? decryptSecret(stored) : stored;
}

export interface SyncableItem {
  id: number;
  /** The live credential. Never log it, never send it to the client. */
  accessToken: string;
  cursor: string | null;
  /** Accounts behind this Item, i.e. the ones transactionsSync may return. */
  accountIds: string[];
}

/**
 * Every Item that still holds a credential, with its accounts.
 *
 * Replaces lib/sync.ts's old `byToken` map, which read an Item's cursor from whichever
 * account row happened to come back first. One row per Item means there is no sibling to
 * choose between — the reason that bug is now unrepresentable rather than merely unlikely.
 *
 * `filterAccountId` narrows to the single Item containing that account, which is what a
 * per-account "sync now" means: the cursor is Item-scoped, so syncing one account still
 * syncs its whole connection.
 */
export async function listSyncableItems(filterAccountId?: string | null): Promise<SyncableItem[]> {
  const { rows } = await db.query<{
    id: number;
    access_token: string;
    cursor: string | null;
    account_ids: string[];
  }>(
    `SELECT i.id,
            i.access_token,
            i.cursor,
            COALESCE(ARRAY_AGG(a.id ORDER BY a.id) FILTER (WHERE a.id IS NOT NULL), '{}') AS account_ids
       FROM plaid_items i
       LEFT JOIN accounts a ON a.plaid_item_id = i.id
      WHERE i.access_token IS NOT NULL
      GROUP BY i.id, i.access_token, i.cursor
      HAVING $1::text IS NULL OR $1 = ANY(ARRAY_AGG(a.id))
      ORDER BY i.id`,
    [filterAccountId ?? null]
  );

  return rows.map((r) => ({
    id: r.id,
    accessToken: readToken(r.access_token),
    cursor: r.cursor,
    accountIds: r.account_ids,
  }));
}

/**
 * Records a completed sync: the new cursor and the success timestamp, at Item grain.
 *
 * `last_synced_at` advancing ONLY on success is what makes a frozen timestamp mean "this
 * connection is failing" rather than "nothing happened" — the whole basis of the staleness
 * model in lib/domain/syncHealth.ts. Kept in one statement with the cursor so the two can
 * never disagree about whether a run succeeded.
 *
 * accounts.last_synced_at is mirrored for the per-account column /accounts still displays.
 */
export async function recordItemSyncSuccess(itemId: number, cursor: string | null): Promise<void> {
  await db.query(
    'UPDATE plaid_items SET cursor = $1, last_synced_at = NOW() WHERE id = $2',
    [cursor, itemId]
  );
  await db.query(
    'UPDATE accounts SET last_synced_at = NOW() WHERE plaid_item_id = $1',
    [itemId]
  );
}

/**
 * Creates or refreshes the Item behind a freshly exchanged public token, returning its id.
 *
 * The cursor reset is the important part, and it now happens at the grain it belongs to. A
 * cursor is scoped to the Item that issued it, so carrying one across a token change makes
 * every later sync fail with INVALID_FIELD "cursor not associated with access_token" — and
 * because last_synced_at only advances on success, the connection then goes silently stale
 * while Plaid keeps reporting the Item as healthy. Conditional, so re-linking and getting the
 * SAME token back keeps the cursor rather than forcing a needless full backfill.
 *
 * Matched on Plaid's own item_id where we have it. Rows backfilled from the old schema have
 * none (it was never stored), so they are matched by token instead and the item_id is filled
 * in on the way past — after which the first branch handles them forever.
 */
export async function upsertItem(params: {
  itemId: string | null;
  accessToken: string;
  institutionId: string | null;
  bank: string | null;
}): Promise<number> {
  const { itemId, accessToken, institutionId, bank } = params;
  const stored = encryptSecret(accessToken);

  if (itemId) {
    const { rows } = await db.query<{ id: number }>(
      `INSERT INTO plaid_items (item_id, access_token, institution_id, bank)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (item_id) DO UPDATE
         SET access_token = EXCLUDED.access_token,
             institution_id = COALESCE(EXCLUDED.institution_id, plaid_items.institution_id),
             bank = COALESCE(plaid_items.bank, EXCLUDED.bank),
             cursor = CASE WHEN plaid_items.access_token IS DISTINCT FROM EXCLUDED.access_token
                           THEN NULL ELSE plaid_items.cursor END
       RETURNING id`,
      [itemId, stored, institutionId, bank]
    );
    return rows[0].id;
  }

  // No item_id from Plaid — fall back to matching on the token, which is all the rows
  // backfilled from the old schema had.
  //
  // Compared after decrypting, one row at a time, rather than with `WHERE access_token = $1`:
  // a fresh IV per encryption means the same token stores as a different string every time, so
  // an equality test would never match and this would silently create a duplicate Item on every
  // reconnect. Scanning is fine here — only pre-migration rows lack an item_id, the set shrinks
  // to nothing as they are re-linked, and this runs once per link, not per sync.
  const candidates = await db.query<{ id: number; access_token: string }>(
    'SELECT id, access_token FROM plaid_items WHERE item_id IS NULL AND access_token IS NOT NULL'
  );
  const match = candidates.rows.find((row) => {
    try {
      return readToken(row.access_token) === accessToken;
    } catch {
      // A row that cannot be decrypted (wrong key, corrupted) must not abort a link attempt.
      log.warn('could not read a stored token while matching items', { itemId: row.id });
      return false;
    }
  });

  const existing = { rows: match ? [{ id: match.id }] : [] };
  if (existing.rows.length > 0) {
    await db.query(
      `UPDATE plaid_items
          SET institution_id = COALESCE($2, institution_id),
              bank = COALESCE(bank, $3)
        WHERE id = $1`,
      [existing.rows[0].id, institutionId, bank]
    );
    return existing.rows[0].id;
  }

  const { rows } = await db.query<{ id: number }>(
    `INSERT INTO plaid_items (item_id, access_token, institution_id, bank)
     VALUES (NULL, $1, $2, $3) RETURNING id`,
    [stored, institutionId, bank]
  );
  log.info('created plaid item without a provider item_id', { itemId: rows[0].id });
  return rows[0].id;
}

/** Points an account at its Item. Used by the link/reconnect path. */
export async function attachAccountToItem(accountId: string, itemId: number): Promise<void> {
  await db.query('UPDATE accounts SET plaid_item_id = $1 WHERE id = $2', [itemId, accountId]);
}
