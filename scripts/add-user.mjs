// Grants a person access to the app.
//
// Passing Cloudflare Access is not sufficient to use b8: lib/auth.ts refuses any identity
// without a row in `users`. That is deliberate — it keeps revocation local and immediate, and
// it means a mis-scoped Access policy (widened to a whole email domain, say) does not silently
// hand over the household's finances. This script is how the second adult gets added.
//
//   DATABASE_URL=... node scripts/add-user.mjs <email> [display name]
//
// Removing access is the mirror image and is deliberately not scripted, because it is a
// one-liner that should be read before it is run:
//   psql "$DATABASE_URL" -c "DELETE FROM users WHERE email = 'them@example.com'"

import pg from 'pg';

const [emailArg, ...nameParts] = process.argv.slice(2);

if (!emailArg) {
  console.error('usage: node scripts/add-user.mjs <email> [display name]');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

// Lowercased to match lib/auth.ts, which lowercases the verified address before looking it up.
// Stored any other way the row simply never matches and the person is locked out with no
// obvious reason why.
const email = emailArg.trim().toLowerCase();
const displayName = nameParts.join(' ').trim() || null;

if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
  console.error(`"${email}" does not look like an email address`);
  process.exit(1);
}

const db = new pg.Client({ connectionString: process.env.DATABASE_URL });
await db.connect();

const { rows } = await db.query(
  `INSERT INTO users (email, display_name, role)
   VALUES ($1, $2, 'member')
   ON CONFLICT (email) DO UPDATE SET display_name = COALESCE(EXCLUDED.display_name, users.display_name)
   RETURNING id, email, role, (xmax = 0) AS created`,
  [email, displayName]
);

await db.end();

const user = rows[0];
console.log(
  user.created
    ? `Added ${user.email} (${user.role}, id ${user.id}).`
    : `${user.email} already had access (${user.role}, id ${user.id}); details refreshed.`
);
console.log('They must also be permitted by the Cloudflare Access policy for this hostname.');
