import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, type JWK } from 'jose';
import { verifyAccessAssertion, AccessVerificationError, __resetJwksCacheForTests } from './accessJwt';

// A real keypair generated per run, with the certs endpoint stubbed. That means these tests
// exercise the actual signature path — including the issuer/audience pinning and the URL the
// module builds — without needing a Cloudflare account, which is why the missing team domain
// and AUD tag never blocked this work.
const TEAM = 'household';
const AUD = 'a'.repeat(64);
const ISSUER = `https://${TEAM}.cloudflareaccess.com`;
const CONFIG = { teamDomain: TEAM, audience: AUD };

let privateKey: CryptoKey;
let publicJwk: JWK;
let otherPrivateKey: CryptoKey;
const KID = 'test-key-1';

beforeEach(async () => {
  __resetJwksCacheForTests();

  const pair = await generateKeyPair('RS256', { extractable: true });
  privateKey = pair.privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: KID, alg: 'RS256', use: 'sig' };

  // A second, unrelated key — stands in for a token signed by someone who is not Cloudflare.
  otherPrivateKey = (await generateKeyPair('RS256', { extractable: true })).privateKey;

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url === `${ISSUER}/cdn-cgi/access/certs`) {
        return new Response(JSON.stringify({ keys: [publicJwk] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('not found', { status: 404 });
    })
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function sign(
  claims: Record<string, unknown>,
  opts: { key?: CryptoKey; issuer?: string; audience?: string; expires?: string } = {}
) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuedAt()
    .setIssuer(opts.issuer ?? ISSUER)
    .setAudience(opts.audience ?? AUD)
    .setExpirationTime(opts.expires ?? '1h')
    .sign(opts.key ?? privateKey);
}

describe('verifyAccessAssertion — accepts a genuine assertion', () => {
  it('returns the email and subject', async () => {
    const token = await sign({ email: 'tom@example.com', sub: 'cf-subject-123' });
    await expect(verifyAccessAssertion(token, CONFIG)).resolves.toEqual({
      email: 'tom@example.com',
      subject: 'cf-subject-123',
    });
  });

  it('lowercases the email, since it is used as a lookup key', async () => {
    const token = await sign({ email: 'Tom@Example.COM', sub: 's' });
    await expect(verifyAccessAssertion(token, CONFIG)).resolves.toMatchObject({
      email: 'tom@example.com',
    });
  });

  it('fetches the key set once and reuses it across requests', async () => {
    // Rebuilding the JWKS per request would refetch on every page load and turn a Cloudflare
    // hiccup into an outage here.
    const token = await sign({ email: 'tom@example.com', sub: 's' });
    await verifyAccessAssertion(token, CONFIG);
    await verifyAccessAssertion(token, CONFIG);
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });
});

describe('verifyAccessAssertion — rejects everything else', () => {
  it('rejects a missing header', async () => {
    await expect(verifyAccessAssertion(null, CONFIG)).rejects.toThrow(AccessVerificationError);
    await expect(verifyAccessAssertion('', CONFIG)).rejects.toThrow(/No Cf-Access-Jwt-Assertion/);
  });

  it('rejects a malformed token', async () => {
    await expect(verifyAccessAssertion('not-a-jwt', CONFIG)).rejects.toThrow(AccessVerificationError);
  });

  it('rejects an expired assertion', async () => {
    const token = await new SignJWT({ email: 'tom@example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuer(ISSUER)
      .setAudience(AUD)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .sign(privateKey);
    await expect(verifyAccessAssertion(token, CONFIG)).rejects.toThrow(AccessVerificationError);
  });

  it('rejects a token minted for a DIFFERENT Access application', async () => {
    // The most important case in a household running several apps behind one Cloudflare
    // account: every Access application is signed with the same team keys, so without the
    // audience pin a token for the phone assistant would open the finance app.
    const token = await sign({ email: 'tom@example.com' }, { audience: 'b'.repeat(64) });
    await expect(verifyAccessAssertion(token, CONFIG)).rejects.toThrow(AccessVerificationError);
  });

  it('rejects a token from a different team domain', async () => {
    const token = await sign({ email: 'tom@example.com' }, { issuer: 'https://someone-else.cloudflareaccess.com' });
    await expect(verifyAccessAssertion(token, CONFIG)).rejects.toThrow(AccessVerificationError);
  });

  it('rejects a token signed by a key Cloudflare does not publish', async () => {
    const token = await sign({ email: 'tom@example.com' }, { key: otherPrivateKey });
    await expect(verifyAccessAssertion(token, CONFIG)).rejects.toThrow(AccessVerificationError);
  });

  it('rejects a tampered payload', async () => {
    const token = await sign({ email: 'tom@example.com', sub: 's' });
    const [header, payload, signature] = token.split('.');
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
    decoded.email = 'attacker@example.com';
    const forged = Buffer.from(JSON.stringify(decoded)).toString('base64url');
    await expect(verifyAccessAssertion(`${header}.${forged}.${signature}`, CONFIG)).rejects.toThrow(
      AccessVerificationError
    );
  });

  it('rejects a validly signed token that carries no email', async () => {
    const token = await sign({ sub: 'cf-subject-123' });
    await expect(verifyAccessAssertion(token, CONFIG)).rejects.toThrow(/no email claim/);
  });

  it('does not leak which check failed', async () => {
    // Distinguishing "wrong audience" from "bad signature" tells an attacker which part of a
    // forged token to fix next.
    const wrongAud = await sign({ email: 'a@b.c' }, { audience: 'b'.repeat(64) });
    const wrongKey = await sign({ email: 'a@b.c' }, { key: otherPrivateKey });
    const messages = await Promise.all(
      [wrongAud, wrongKey].map((t) =>
        verifyAccessAssertion(t, CONFIG).then(() => '', (e) => (e as Error).message)
      )
    );
    expect(messages[0]).toBe(messages[1]);
    expect(messages[0]).toBe('Access assertion failed verification');
  });
});
