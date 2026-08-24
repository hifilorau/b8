import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { encryptSecret, decryptSecret, isEncrypted } from './crypto';

// A fixed, obviously-fake key. Generated the same way the real one is (32 random bytes,
// base64) but committed on purpose: it is a test fixture, not a credential.
const TEST_KEY = Buffer.alloc(32, 7).toString('base64');
const PLAID_SHAPED_TOKEN = 'access-sandbox-a1b2c3d4-5678-90ab-cdef-1234567890ab';

let original: string | undefined;
beforeEach(() => {
  original = process.env.TOKEN_ENCRYPTION_KEY;
  process.env.TOKEN_ENCRYPTION_KEY = TEST_KEY;
});
afterEach(() => {
  if (original === undefined) delete process.env.TOKEN_ENCRYPTION_KEY;
  else process.env.TOKEN_ENCRYPTION_KEY = original;
});

describe('encryptSecret / decryptSecret', () => {
  it('round-trips a Plaid-shaped access token', () => {
    expect(decryptSecret(encryptSecret(PLAID_SHAPED_TOKEN))).toBe(PLAID_SHAPED_TOKEN);
  });

  it('never emits the plaintext inside the payload', () => {
    // The one property that matters for a database dump: reading the column must not reveal
    // the token, in whole or in part.
    const payload = encryptSecret(PLAID_SHAPED_TOKEN);
    expect(payload).not.toContain(PLAID_SHAPED_TOKEN);
    expect(payload).not.toContain('access-sandbox');
  });

  it('produces a different payload every time for the same input', () => {
    // A fresh IV per call. This is exactly why nothing may key, join or compare on the
    // column — the constraint that forced plaid_items to exist before this could land.
    const a = encryptSecret(PLAID_SHAPED_TOKEN);
    const b = encryptSecret(PLAID_SHAPED_TOKEN);
    expect(a).not.toBe(b);
    expect(decryptSecret(a)).toBe(decryptSecret(b));
  });

  it('tags every payload with its version', () => {
    expect(encryptSecret(PLAID_SHAPED_TOKEN).startsWith('v1:')).toBe(true);
  });

  it('round-trips an empty string and multi-byte characters', () => {
    expect(decryptSecret(encryptSecret(''))).toBe('');
    expect(decryptSecret(encryptSecret('café — 日本語 🔐'))).toBe('café — 日本語 🔐');
  });
});

describe('decryptSecret — rejects rather than returning something wrong', () => {
  // GCM authenticates, so corruption fails loudly here instead of yielding a plausible-looking
  // token that would be sent to Plaid and surface as a confusing auth error far from the cause.
  it('throws when the ciphertext has been altered', () => {
    const parts = encryptSecret(PLAID_SHAPED_TOKEN).split(':');
    const ct = Buffer.from(parts[3], 'base64');
    ct[0] ^= 0xff;
    parts[3] = ct.toString('base64');
    expect(() => decryptSecret(parts.join(':'))).toThrow();
  });

  it('throws when the auth tag has been altered', () => {
    const parts = encryptSecret(PLAID_SHAPED_TOKEN).split(':');
    const tag = Buffer.from(parts[2], 'base64');
    tag[0] ^= 0xff;
    parts[2] = tag.toString('base64');
    expect(() => decryptSecret(parts.join(':'))).toThrow();
  });

  it('throws when decrypting under a different key', () => {
    const payload = encryptSecret(PLAID_SHAPED_TOKEN);
    process.env.TOKEN_ENCRYPTION_KEY = Buffer.alloc(32, 9).toString('base64');
    expect(() => decryptSecret(payload)).toThrow();
  });

  it('rejects a malformed or unversioned payload', () => {
    expect(() => decryptSecret('not-encrypted-at-all')).toThrow(/malformed/i);
    expect(() => decryptSecret('v2:a:b:c')).toThrow(/version/i);
  });
});

describe('key configuration', () => {
  it('names the missing variable and how to generate one', () => {
    delete process.env.TOKEN_ENCRYPTION_KEY;
    expect(() => encryptSecret('x')).toThrow(/TOKEN_ENCRYPTION_KEY/);
    expect(() => encryptSecret('x')).toThrow(/openssl rand -base64 32/);
  });

  it('rejects a key that is the wrong length rather than padding it', () => {
    process.env.TOKEN_ENCRYPTION_KEY = Buffer.alloc(16, 1).toString('base64');
    expect(() => encryptSecret('x')).toThrow(/32 bytes/);
  });
});

describe('isEncrypted', () => {
  it('recognises this module’s own output', () => {
    expect(isEncrypted(encryptSecret(PLAID_SHAPED_TOKEN))).toBe(true);
  });

  it('treats a plaintext token or null as not encrypted', () => {
    // What lets the read path tolerate a not-yet-migrated row, so the backfill can run
    // against a live app instead of needing a stop-the-world window.
    expect(isEncrypted(PLAID_SHAPED_TOKEN)).toBe(false);
    expect(isEncrypted(null)).toBe(false);
  });
});
