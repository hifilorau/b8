// Verifies the assertion Cloudflare Access puts on every request it lets through.
//
// Why the origin verifies this at all, when Access already checked it: Access enforces at
// Cloudflare's edge, and the origin only ever sees traffic that arrived through the tunnel
// BY CONVENTION. A routing change, a second ingress rule, a tunnel pointed at the wrong
// service, or anyone who can reach the container directly all bypass that edge check without
// tripping anything. Verifying the signature here is what makes the identity wall a property
// of the application rather than of the network drawing around it.
//
// Uses `jose` rather than hand-rolling the verification. The repo's stated preference is raw
// building blocks over frameworks, and this is the deliberate exception: JWKS fetching, key
// caching, key rotation and constant-time signature checking are exactly the things that look
// simple and are quietly wrong when written by hand.

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export interface VerifiedIdentity {
  /** The address Access authenticated. Lowercased, since it is used as a lookup key. */
  email: string;
  /** Cloudflare's stable subject id for the user. */
  subject: string;
}

export class AccessVerificationError extends Error {}

/**
 * One JWKS per team domain, cached at module scope.
 *
 * createRemoteJWKSet handles fetching, caching and refetching on an unknown `kid`, which is
 * what makes Cloudflare's key rotation a non-event. Building a new one per request would
 * refetch the key set on every page load and turn an outage at Cloudflare into an outage here.
 */
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(teamDomain: string) {
  const cached = jwksCache.get(teamDomain);
  if (cached) return cached;

  const url = new URL(`https://${teamDomain}.cloudflareaccess.com/cdn-cgi/access/certs`);
  const jwks = createRemoteJWKSet(url);
  jwksCache.set(teamDomain, jwks);
  return jwks;
}

/** Cloudflare puts the address in `email`; the rest of the payload varies by identity provider. */
function extractEmail(payload: JWTPayload): string {
  const email = payload.email;
  if (typeof email !== 'string' || email.length === 0) {
    throw new AccessVerificationError('Access assertion carries no email claim');
  }
  return email.toLowerCase();
}

/**
 * Verifies the `Cf-Access-Jwt-Assertion` header.
 *
 * Both `issuer` and `audience` are pinned, and the audience is the one that matters most in a
 * household running several apps behind one Cloudflare account: every Access application signs
 * with the SAME team keys, so a signature check alone would accept a token minted for the
 * phone assistant against the finance app. The AUD tag is what scopes it to this application.
 *
 * Throws on anything short of a fully valid assertion — never returns a partial or "probably
 * fine" result. `jwtVerify` already enforces expiry and not-before.
 */
export async function verifyAccessAssertion(
  assertion: string | null,
  config: { teamDomain: string; audience: string }
): Promise<VerifiedIdentity> {
  if (!assertion) {
    throw new AccessVerificationError('No Cf-Access-Jwt-Assertion header present');
  }

  try {
    const { payload } = await jwtVerify(assertion, getJwks(config.teamDomain), {
      issuer: `https://${config.teamDomain}.cloudflareaccess.com`,
      audience: config.audience,
    });

    const subject = typeof payload.sub === 'string' ? payload.sub : '';
    return { email: extractEmail(payload), subject };
  } catch (err) {
    if (err instanceof AccessVerificationError) throw err;
    // Deliberately not the underlying message: jose distinguishes "wrong audience" from
    // "bad signature" from "expired", and reflecting that back tells an attacker which part
    // of a forged token to fix. The real reason is logged server-side by the caller.
    throw new AccessVerificationError('Access assertion failed verification');
  }
}

/** Test seam: the JWKS cache is module-scoped, so tests must be able to clear it. */
export function __resetJwksCacheForTests(): void {
  jwksCache.clear();
}
