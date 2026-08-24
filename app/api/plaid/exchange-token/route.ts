import { NextRequest } from 'next/server';
import { CountryCode } from 'plaid';
import { plaidClient } from '@/lib/plaid';
import db from '@/lib/db';
import type { ApiResponse, LinkedAccountSummary } from '@/shared/types';
import { createLogger } from '@/lib/logger';
import { upsertItem } from '@/lib/plaidItems';

const log = createLogger('exchange-token');

export async function POST(req: NextRequest) {
  const { public_token } = await req.json();

  if (!public_token || typeof public_token !== 'string') {
    return Response.json(
      { success: false, error: { code: 'INVALID_INPUT', message: 'public_token is required' } } satisfies ApiResponse<never>,
      { status: 400 }
    );
  }

  try {
    const exchangeRes = await plaidClient.itemPublicTokenExchange({ public_token });
    const { access_token } = exchangeRes.data;

    const [accountsRes, itemRes] = await Promise.all([
      plaidClient.accountsGet({ access_token }),
      plaidClient.itemGet({ access_token }),
    ]);
    const accounts = accountsRes.data.accounts;
    const institutionId = itemRes.data.item.institution_id;
    // itemGet was already being called for institution_id; the Item's own id was fetched and
    // thrown away. It is the stable key for the connection, so it is what the Item row is
    // matched on from here.
    const providerItemId = itemRes.data.item.item_id;

    let bankName: string | null = null;
    if (institutionId) {
      try {
        const instRes = await plaidClient.institutionsGetById({
          institution_id: institutionId,
          country_codes: [CountryCode.Us],
        });
        bankName = instRes.data.institution.name;
      } catch {
        // non-fatal — bank name stays null
      }
    }

    // Sequential rather than Promise.all: each account's outcome (genuinely new vs. a
    // reconnect merged into an existing row) has to be known before it can be reported back,
    // and correctly detecting "new" needs ON CONFLICT DO NOTHING's rowCount, which a
    // fire-and-forget DO UPDATE can't give — that always affects exactly one row either way,
    // so the old code's `rowCount === 1` check ran on every account, insert or not.
    // One row for the connection, created (or refreshed) before any account references it.
    // The cursor reset on a changed token happens in here now, at the grain a cursor actually
    // belongs to — see lib/plaidItems.ts.
    const itemId = await upsertItem({
      itemId: providerItemId,
      accessToken: access_token,
      institutionId: institutionId ?? null,
      bank: bankName,
    });

    const newlyLinked: LinkedAccountSummary[] = [];

    for (const a of accounts) {
      const insertRes = await db.query(
        `INSERT INTO accounts (id, name, type, subtype, mask, persistent_account_id, plaid_item_id, bank)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO NOTHING`,
        [a.account_id, a.name, a.type, a.subtype ?? null, a.mask ?? null, a.persistent_account_id ?? null, itemId, bankName]
      );

      if (insertRes.rowCount === 0) {
        // This exact id was already tracked — a plain reconnect. Refresh its identifiers and
        // point it at the Item, but it is not new: whatever valuation_mode it already has
        // stands. The cursor CASE that used to live here is gone; the cursor belongs to the
        // Item and upsertItem above has already decided whether the token changed.
        await db.query(
          `UPDATE accounts SET name = $1, mask = $2, persistent_account_id = $3,
                  plaid_item_id = $4, bank = COALESCE(bank, $5)
             WHERE id = $6`,
          [a.name, a.mask ?? null, a.persistent_account_id ?? null, itemId, bankName, a.account_id]
        );
        continue;
      }

      // Freshly inserted under a.account_id — but may still be reconnecting an account we
      // track under a DIFFERENT id (Plaid reissued it). Match by the strongest signal
      // available — persistent_account_id, then mask+type, then name — and if found, keep
      // the EXISTING row's id (so transaction history stays attached), repoint it at the new
      // access_token, and drop the freshly-inserted duplicate. Only a match-free insert is
      // reported as newly linked below.
      const dup = await db.query<{ id: string }>(
        `SELECT id FROM accounts
         WHERE id != $4
           AND (
             ($1::text IS NOT NULL AND persistent_account_id = $1)
             OR ($2::text IS NOT NULL AND mask = $2 AND type = $3)
             OR (name = $5 AND type = $3)
           )
         ORDER BY (persistent_account_id = $1) DESC, (mask = $2) DESC
         LIMIT 1`,
        [a.persistent_account_id ?? null, a.mask ?? null, a.type, a.account_id, a.name]
      );

      if (dup.rows.length > 0) {
        const existingId = dup.rows[0].id;
        // The `cursor = NULL` this used to carry is no longer needed, and its absence is the
        // point: moving an account between Items cannot strand it on the wrong cursor, because
        // the cursor it syncs with is whichever one its new Item holds.
        await db.query(
          `UPDATE accounts SET mask = $1, persistent_account_id = $2,
                  plaid_item_id = $3, bank = COALESCE(bank, $4)
             WHERE id = $5`,
          [a.mask ?? null, a.persistent_account_id ?? null, itemId, bankName, existingId]
        );
        await db.query('DELETE FROM accounts WHERE id = $1', [a.account_id]);
        continue;
      }

      newlyLinked.push({ id: a.account_id, name: a.name, type: a.type, subtype: a.subtype ?? null, mask: a.mask ?? null });
    }

    return Response.json({
      success: true,
      data: { accounts_linked: accounts.length, new_accounts: newlyLinked },
    } satisfies ApiResponse<{ accounts_linked: number; new_accounts: LinkedAccountSummary[] }>);
  } catch (err) {
    // Message only — see create-link-token/route.ts for why the raw error object must never
    // be logged here (it can carry the live Plaid client-id/secret via axios's error.config).
    log.error('request failed', { error: err instanceof Error ? err.message : String(err) });
    return Response.json(
      { success: false, error: { code: 'PLAID_ERROR', message: 'Failed to exchange token' } } satisfies ApiResponse<never>,
      { status: 500 }
    );
  }
}
