// User lookup, split out from lib/auth.ts so that proxy.ts can use it.
//
// The split exists for one concrete reason: lib/auth.ts imports `next/headers`, which is only
// available inside a rendering request, so proxy.ts cannot import it. Without this file the
// "is this a known user" check could only run in pages and routes — and that is exactly the
// hole this module was written to close, after a test showed a verified-but-unknown identity
// loading /dashboard with a 200 because nothing on that path happened to call requireUser().
//
// Authentication and authorization are genuinely different questions here. Cloudflare Access
// answers "is this person who they say they are". This answers "may they see this household's
// finances". Keeping the second one local is what makes revocation immediate and independent
// of a Cloudflare policy change, and what contains a mis-scoped Access policy.

import db from './db';
import { createLogger } from './logger';

const log = createLogger('users');

export interface AppUser {
  id: number;
  email: string;
  displayName: string | null;
  role: 'owner' | 'member';
}

interface UserRow {
  id: number;
  email: string;
  display_name: string | null;
  role: 'owner' | 'member';
}

const toUser = (r: UserRow): AppUser => ({
  id: r.id,
  email: r.email,
  displayName: r.display_name,
  role: r.role,
});

/**
 * Deliberately uncached.
 *
 * A cache would mean revoked access keeps working until it expires, and immediate local
 * revocation is the main thing this table buys over relying on Access alone. One indexed
 * lookup on a UNIQUE column, for a household-sized request volume, is not worth trading that
 * for.
 */
export async function findUserByEmail(email: string): Promise<AppUser | null> {
  const { rows } = await db.query<UserRow>(
    'SELECT id, email, display_name, role FROM users WHERE email = $1',
    [email]
  );
  return rows.length > 0 ? toUser(rows[0]) : null;
}

/** Best-effort: worth knowing when an account was last used, never worth failing a request. */
export function touchLastSeen(userId: number): void {
  db.query('UPDATE users SET last_seen_at = NOW() WHERE id = $1', [userId]).catch((err) =>
    log.warn('could not update last_seen_at', {
      error: err instanceof Error ? err.message : String(err),
    })
  );
}

/**
 * Creates the very first user, and only the very first.
 *
 * The guard is "the table is empty", enforced in SQL rather than by a prior read, so two
 * simultaneous first requests cannot both insert. That is also what stops BOOTSTRAP_ADMIN_EMAIL
 * being a standing back door: once any user exists it can never create another, so leaving it
 * set is harmless and learning its value gains an attacker nothing.
 */
export async function bootstrapFirstUser(email: string): Promise<AppUser | null> {
  const bootstrap = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
  if (!bootstrap || bootstrap !== email) return null;

  const { rows } = await db.query<UserRow>(
    `INSERT INTO users (email, role, last_seen_at)
     SELECT $1, 'owner', NOW()
      WHERE NOT EXISTS (SELECT 1 FROM users)
     RETURNING id, email, display_name, role`,
    [email]
  );

  if (rows.length === 0) return null;

  log.info('bootstrapped the first user from BOOTSTRAP_ADMIN_EMAIL', { userId: rows[0].id });
  return toUser(rows[0]);
}

/**
 * The authorization decision, in one place: a verified email either maps to a user or does not.
 * Returns null for an identity that passed Access but has no row here.
 */
export async function authorizeEmail(email: string): Promise<AppUser | null> {
  const existing = await findUserByEmail(email);
  if (existing) {
    touchLastSeen(existing.id);
    return existing;
  }
  return bootstrapFirstUser(email);
}
