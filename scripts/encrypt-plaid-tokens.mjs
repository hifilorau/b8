// One-shot: encrypts any plaintext Plaid access token already in plaid_items.
//
// Safe to run against a live database and safe to run twice. Rows are matched on NOT already
// having the version prefix, so an interrupted run resumes and a second run is a no-op — the
// same reason lib/plaidItems.ts tolerates a mixed state on read rather than assuming every row
// has been converted.
//
//   TOKEN_ENCRYPTION_KEY=... DATABASE_URL=... npm run encrypt:tokens
//
// Node prints a MODULE_TYPELESS_PACKAGE_JSON warning when this imports lib/crypto.ts, because
// package.json declares no "type". It is about reparsing cost, not correctness, and adding
// "type": "module" to fix it is not worth the risk: Next's standalone output ships a CommonJS
// server.js, so flipping the whole package to ESM could break the production container for a
// cosmetic warning on a script that runs once.
//
// Back up first. If TOKEN_ENCRYPTION_KEY is later lost, these tokens are unrecoverable and
// every institution has to be re-linked through Plaid Link — transaction history survives
// (it is keyed on accounts, not on the credential), but the connections do not.

import pg from 'pg';
import { encryptSecret, isEncrypted } from '../lib/crypto.ts';

for (const v of ['DATABASE_URL', 'TOKEN_ENCRYPTION_KEY']) {
  if (!process.env[v]) {
    console.error(`${v} is not set`);
    process.exit(1);
  }
}

const db = new pg.Client({ connectionString: process.env.DATABASE_URL });
await db.connect();

const { rows } = await db.query(
  'SELECT id, access_token FROM plaid_items WHERE access_token IS NOT NULL ORDER BY id'
);

let encrypted = 0;
let alreadyDone = 0;

try {
  await db.query('BEGIN');
  for (const row of rows) {
    if (isEncrypted(row.access_token)) {
      alreadyDone++;
      continue;
    }
    await db.query('UPDATE plaid_items SET access_token = $1 WHERE id = $2', [
      encryptSecret(row.access_token),
      row.id,
    ]);
    encrypted++;
  }
  await db.query('COMMIT');
} catch (err) {
  await db.query('ROLLBACK');
  // Message only — never the row or the error object, either of which can carry the token.
  console.error(`Failed, rolled back: ${err instanceof Error ? err.message : String(err)}`);
  await db.end();
  process.exit(1);
}

await db.end();
console.log(`Encrypted ${encrypted} token(s); ${alreadyDone} already encrypted.`);
