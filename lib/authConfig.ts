// Resolves how the app authenticates, and refuses impossible combinations at startup.
//
// The whole point of this module is one rule: BEING REACHABLE AND BEING AUTHENTICATED MUST BE
// A SINGLE DECISION. Left as two independent switches, the failure mode is not exotic — you
// add a hostname to serve the app through a tunnel, forget the identity variables, and an app
// holding real bank data is answering the public internet with no login. Nothing would report
// that; it would just work, which is the problem. So a non-loopback host without Access
// configuration is a startup error, not a running app.
//
// Pure and env-injected rather than reading process.env directly, so every combination is
// unit-testable without booting a server — the same stance lib/hostGuard.ts takes.

import { parseAllowedHosts } from './hostGuard';

export type AuthMode =
  /** No identity layer. Correct ONLY while the app is loopback-only. */
  | { kind: 'local' }
  /** Every request must carry a valid Cloudflare Access assertion AND resolve to a known user. */
  | { kind: 'access'; teamDomain: string; audience: string }
  /** Explicitly disabled for local development. Cannot be reached when NODE_ENV=production. */
  | { kind: 'dev-bypass' };

export interface AuthEnv {
  NODE_ENV?: string;
  ALLOWED_HOSTS?: string;
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  AUTH_DEV_BYPASS?: string;
}

export class AuthConfigError extends Error {}

/**
 * Throws AuthConfigError rather than degrading to something permissive. A misconfigured
 * finance app should fail to start, loudly, at deploy time — the alternative is discovering
 * the gap from someone else's traffic.
 */
export function resolveAuthMode(env: AuthEnv): AuthMode {
  const isProduction = env.NODE_ENV === 'production';
  const teamDomain = env.CF_ACCESS_TEAM_DOMAIN?.trim();
  const audience = env.CF_ACCESS_AUD?.trim();
  const configured = Boolean(teamDomain) && Boolean(audience);

  // Half-configured is always an error, in every environment. It reads like protection while
  // providing none, which is worse than plainly having none.
  if (Boolean(teamDomain) !== Boolean(audience)) {
    throw new AuthConfigError(
      'CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD must be set together. ' +
        'Both are required to verify a Cloudflare Access assertion: the team domain identifies ' +
        'the signing keys, and the AUD tag is what stops a token minted for one Access ' +
        'application being replayed against another.'
    );
  }

  if (env.AUTH_DEV_BYPASS === '1') {
    if (isProduction) {
      throw new AuthConfigError(
        'AUTH_DEV_BYPASS=1 is set with NODE_ENV=production. This flag disables authentication ' +
          'entirely and exists only for local development; it will not activate in production.'
      );
    }
    return { kind: 'dev-bypass' };
  }

  // The interlock. `extraHosts` is exactly the set that makes the app reachable under a name
  // other than loopback, so it is the precise trigger for requiring an identity layer.
  const extraHosts = parseAllowedHosts(env.ALLOWED_HOSTS);
  if (extraHosts.length > 0 && !configured) {
    throw new AuthConfigError(
      `ALLOWED_HOSTS names ${extraHosts.length} non-loopback host(s) (${extraHosts.join(', ')}) ` +
        'but CF_ACCESS_TEAM_DOMAIN / CF_ACCESS_AUD are not set. That combination would serve ' +
        'an app with no authentication to anything that can reach that hostname. Either ' +
        'configure Cloudflare Access, or clear ALLOWED_HOSTS to keep the app loopback-only.'
    );
  }

  if (configured) {
    return { kind: 'access', teamDomain: teamDomain!, audience: audience! };
  }

  return { kind: 'local' };
}

/** True when requests must present a verified identity. */
export function requiresVerification(mode: AuthMode): boolean {
  return mode.kind === 'access';
}
