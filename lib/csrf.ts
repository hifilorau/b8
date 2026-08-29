// Rejects cross-site state-changing requests.
//
// Why this is needed even behind Cloudflare Access: Access authenticates with a COOKIE
// (CF_Authorization). A browser attaches cookies according to its own rules, not according to
// who initiated the request — so a page on any other origin can cause the victim's browser to
// POST here, and that request arrives already authenticated. Access says "this is Tom"; it
// cannot say "Tom meant to do this". Every mutating route in this app is one such request away
// from a hostile page: delete an account, wipe a category, trigger an import.
//
// The check is header-based rather than token-based deliberately. A synchroniser token needs
// somewhere to live (a session store or a second cookie) and somewhere to be attached (every
// one of 24 client fetch call sites). Origin and Sec-Fetch-Site are set by the browser itself,
// cannot be altered by page script, and need no plumbing — which for a single-household app is
// the better trade.
//
// Pure, so the whole matrix is testable without a server, matching lib/hostGuard.ts.

/** Methods defined as safe by RFC 9110 — they must not change state, so they are not gated. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export interface CsrfRequestInfo {
  method: string;
  /** The `Origin` header, if the browser sent one. */
  origin: string | null;
  /** The `Sec-Fetch-Site` header, if the browser sent one. */
  secFetchSite: string | null;
  /** The `Host` header — what the request was addressed to. */
  host: string | null;
}

export type CsrfVerdict = { ok: true } | { ok: false; reason: string };

/**
 * Absent headers are ALLOWED, and that is a deliberate decision rather than an oversight.
 *
 * Every browser in current use sends `Sec-Fetch-Site`, and sends `Origin` on cross-origin
 * requests. Absence therefore means the caller is not a browser — curl, a script, the health
 * check — and a non-browser client has no ambient cookie jar to be tricked into spending. It
 * cannot be a confused deputy, because there is no deputy. Rejecting on absence would break
 * legitimate operational access while adding no protection against the actual attack, which
 * requires a browser to carry someone's credentials.
 */
export function checkCsrf(req: CsrfRequestInfo): CsrfVerdict {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return { ok: true };

  // `same-site` is rejected alongside `cross-site`: it means a different origin on a shared
  // registrable domain. For a household running several apps under one domain, that is exactly
  // the neighbour we do not want initiating writes here.
  if (req.secFetchSite === 'cross-site' || req.secFetchSite === 'same-site') {
    return { ok: false, reason: `Sec-Fetch-Site: ${req.secFetchSite}` };
  }

  if (req.origin !== null && req.origin !== 'null') {
    let originHost: string;
    try {
      originHost = new URL(req.origin).host;
    } catch {
      return { ok: false, reason: 'Origin header is not a valid URL' };
    }
    if (!req.host || originHost.toLowerCase() !== req.host.toLowerCase()) {
      // Compared host-to-host, including port: http://localhost:3000 and http://localhost:3001
      // are genuinely different origins and one must not be able to write to the other.
      return { ok: false, reason: 'Origin does not match Host' };
    }
  }

  return { ok: true };
}
