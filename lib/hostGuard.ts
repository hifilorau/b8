// The pure predicate behind proxy.ts's Host allowlist — kept DB-free and
// unit-testable per ROADMAP.md §2's RBAC-pure-predicate pattern.
//
// The dev/start scripts already bind to 127.0.0.1 only (see package.json), so this isn't
// closing a network-reachability gap — it's defense against DNS rebinding: a page on any
// origin can get a victim's browser to send a same-machine request to this server with an
// attacker-controlled `Host` header (DNS for the attacker's domain resolves to 127.0.0.1
// after the browser's initial same-origin checks pass), bypassing same-origin protections
// entirely because the request really is being sent to 127.0.0.1. Rejecting anything but
// the expected Host values closes that off — the same mitigation webpack-dev-server and
// Vite ship by default for exactly this class of attack against local dev servers.
//
// Serving through a reverse proxy or a Cloudflare Tunnel changes the picture: `cloudflared`
// forwards the ORIGINAL public Host, so a loopback-only allowlist rejects every proxied
// request with a 403 — including the App Router's RSC payload requests, which are addressed
// to the page URL itself and so are matched by the proxy too. That is why the allowlist is
// extensible via ALLOWED_HOSTS rather than hardcoded.
//
// Note what this is NOT, once a public hostname is added: past that point the whole internet
// can reach the name, so a Host check is no longer any kind of authorization boundary — it
// only answers "did this request arrive under the name we expect". Authentication has to come
// from somewhere else (Cloudflare Access + origin-side verification of its assertion).

const LOOPBACK_HOSTNAMES = ['localhost', '127.0.0.1', '[::1]', '0.0.0.0'];

/**
 * Extracts the hostname from a `Host` header value, lowercased.
 *
 * Host headers carry "hostname:port" (or a bracketed IPv6 literal); split on the last
 * colon so an IPv6 literal's internal colons aren't mistaken for the port separator.
 */
function hostnameOf(hostHeader: string): string {
  const lastColon = hostHeader.lastIndexOf(':');
  const bracketClose = hostHeader.lastIndexOf(']');
  const hostname = lastColon > bracketClose ? hostHeader.slice(0, lastColon) : hostHeader;
  return hostname.toLowerCase();
}

/**
 * Parses the comma-separated ALLOWED_HOSTS env var into hostnames.
 *
 * Entries are run through the same `hostnameOf` normalization as the incoming header, so a
 * configured value written with a port ("finance.example.com:443") still matches a request
 * that arrives without one, rather than silently never matching. Pure and separated from
 * `process.env` so the parsing is testable on its own.
 */
export function parseAllowedHosts(raw: string | null | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map(hostnameOf);
}

/**
 * `extraHosts` is additive — the loopback names are always allowed, so configuring a public
 * hostname never costs local recovery access to the origin (which is the documented way back
 * in if a tunnel or an identity provider is what broke).
 *
 * Entries are normalized here rather than trusted to arrive normalized. `parseAllowedHosts`
 * already lowercases, so this is belt-and-braces for that path — but it is what makes the
 * predicate correct for any *other* caller, and a Host comparison that silently fails to
 * match is the kind of bug that presents as "the tunnel is just broken".
 */
export function isAllowedHost(hostHeader: string | null, extraHosts: readonly string[] = []): boolean {
  if (!hostHeader) return false;
  const hostname = hostnameOf(hostHeader);
  return (
    LOOPBACK_HOSTNAMES.includes(hostname) ||
    extraHosts.some((extra) => hostnameOf(extra) === hostname)
  );
}
