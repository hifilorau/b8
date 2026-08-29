// Resolves the request's user, and is the last thing standing between a verified identity and
// the household's financial data.
//
// The split of responsibility with proxy.ts is worth stating, because it is what makes this
// safe rather than ceremonial:
//
//   proxy.ts  — verifies the Cloudflare Access signature and injects a TRUSTED email header.
//               It also deletes any inbound copy of that header, so a client cannot supply one.
//   this file — turns that email into a user row, and refuses if there isn't one.
//
// The header is trusted here ONLY because proxy.ts guarantees it was overwritten on every
// request. If that guarantee ever breaks, this becomes a header-spoofing hole, which is why
// the strip is asserted by a test rather than left as a comment.

import { headers } from 'next/headers';
import { resolveAuthMode } from './authConfig';
import { findUserByEmail, type AppUser } from './users';

/** Set by proxy.ts after verification. Never read from a client-supplied request. */
export const VERIFIED_EMAIL_HEADER = 'x-b8-user-email';

export type CurrentUser = AppUser;

export class UnauthorizedError extends Error {}

/**
 * The user for this request, or null.
 *
 * By the time this runs, proxy.ts has already verified the assertion AND confirmed the email
 * maps to a user row — an unknown identity never reaches a page. So this is a lookup for
 * display purposes, not a gate, and it is deliberately not the last line of defence.
 *
 * In `local` and `dev-bypass` modes there is no verified identity, which is correct rather
 * than a gap: those modes are only reachable when the app is loopback-only, because
 * lib/authConfig.ts refuses to start otherwise.
 */
export async function getCurrentUser(): Promise<CurrentUser | null> {
  const mode = resolveAuthMode(process.env);
  if (mode.kind !== 'access') return null;

  const email = (await headers()).get(VERIFIED_EMAIL_HEADER);
  if (!email) return null;

  return findUserByEmail(email);
}

/**
 * For route handlers and pages that must not proceed without a user.
 *
 * Throws rather than returning null so a caller cannot forget to check — the failure mode of
 * an ignored return value here is serving someone else's bank balances.
 */
export async function requireUser(): Promise<CurrentUser> {
  const mode = resolveAuthMode(process.env);
  if (mode.kind !== 'access') {
    // Loopback-only, so there is nobody to identify. Returning a sentinel keeps call sites
    // uniform instead of making every one of them branch on the mode.
    return { id: 0, email: 'local', displayName: 'Local', role: 'owner' };
  }

  const user = await getCurrentUser();
  if (!user) throw new UnauthorizedError('No known user for this request');
  return user;
}
