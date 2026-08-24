// Envelope encryption for provider credentials at rest — today just Plaid access tokens.
//
// What this actually buys, stated plainly: the key lives in the environment, not in Postgres,
// so a database dump, a stolen backup file, or read access to the database alone no longer
// yields usable bank credentials. It does NOT defend against compromise of the host running
// the app, which has both the key and the ciphertext. That is a real limit, and the reason
// tested, encrypted backups matter at least as much as this file does — a leaked backup is
// the likeliest way these values escape, and it is precisely the case this covers.
//
// AES-256-GCM rather than CBC or a raw stream: GCM authenticates, so a tampered ciphertext
// fails loudly on decrypt instead of silently producing a wrong token that would then be sent
// to Plaid. Every payload carries a fresh random IV, which is what makes two encryptions of
// the same token differ — and why nothing may key, join or compare on this column. That
// constraint is exactly why plaid_items had to exist first.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12; // 96 bits, the size GCM is specified for
const KEY_BYTES = 32;

/** Prefix on every payload so the algorithm and layout can change without guessing later. */
const VERSION = 'v1';

/**
 * Validated lazily rather than at import, unlike lib/db.ts's DATABASE_URL check.
 *
 * Deliberate: the key is only needed on the paths that touch a Plaid credential, and throwing
 * at import would take down every unrelated page and route — the budget grid, the property
 * views, the whole app — for a variable most of them never read. Failing at the point of use
 * keeps an unconfigured key an error about Plaid, which is what it is.
 */
function getKey(): Buffer {
  const raw = process.env.TOKEN_ENCRYPTION_KEY;
  if (!raw) {
    throw new Error(
      'TOKEN_ENCRYPTION_KEY is not set — required to read or write Plaid credentials. ' +
        'Generate one with: openssl rand -base64 32'
    );
  }
  const key = Buffer.from(raw, 'base64');
  if (key.length !== KEY_BYTES) {
    throw new Error(
      `TOKEN_ENCRYPTION_KEY must be ${KEY_BYTES} bytes of base64 (got ${key.length}). ` +
        'Generate one with: openssl rand -base64 32'
    );
  }
  return key;
}

/**
 * Returns `v1:<iv>:<authTag>:<ciphertext>`, all base64.
 *
 * Fixed-width, colon-delimited and version-led so a future key rotation or algorithm change
 * can identify what it is looking at rather than inferring it from length.
 */
export function encryptSecret(plaintext: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, getKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [VERSION, iv.toString('base64'), authTag.toString('base64'), ciphertext.toString('base64')].join(':');
}

/**
 * Throws on a tampered or truncated payload rather than returning anything — a silently wrong
 * token would be sent to Plaid and fail as a confusing auth error far from the real cause.
 */
export function decryptSecret(payload: string): string {
  const parts = payload.split(':');
  if (parts.length !== 4) {
    throw new Error('Encrypted secret is malformed (expected 4 colon-delimited parts)');
  }
  const [version, ivB64, tagB64, ctB64] = parts;
  if (version !== VERSION) {
    throw new Error(`Unsupported encrypted secret version: ${version}`);
  }

  const decipher = createDecipheriv(ALGORITHM, getKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]).toString('utf8');
}

/**
 * True for anything this module produced. Lets the read path accept a value that has not been
 * migrated yet without trying to decrypt it and failing — the backfill can then run while the
 * app is up, rather than requiring a stop-the-world window.
 */
export function isEncrypted(value: string | null): boolean {
  return value !== null && value.startsWith(`${VERSION}:`);
}
