import type { NextConfig } from 'next';

// Applied to every response. These are cheap, and the ones that matter here are the ones that
// limit what a successful XSS or a hostile embedder could do with a page that renders bank
// balances and can trigger transfers of categorisation, imports and syncs.
const securityHeaders = [
  // No framing at all. There is no legitimate reason to embed this app, and clickjacking a
  // "delete account" button is a real outcome.
  { key: 'X-Frame-Options', value: 'DENY' },
  // Stops the browser guessing a content type and, say, executing an uploaded CSV as script.
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  // Referrers can carry account and property ids in the path; send the origin only, and only
  // to same-protocol destinations.
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  // Nothing here needs any of these, so refuse them rather than leaving them to the default.
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  // Only meaningful over HTTPS, which in practice means through the tunnel. Harmless on
  // loopback HTTP, where browsers ignore it.
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
];

// CSP is separate because one directive here is a genuine compromise and should be visible
// rather than buried in the list above.
//
// 'unsafe-inline' for scripts: the App Router bootstraps hydration with inline script tags
// carrying the RSC payload. Removing it requires per-request nonces threaded through the
// document, which Next does not currently expose in a way that survives static optimisation.
// So this CSP is a defence-in-depth layer that constrains where code and data can be LOADED
// from and where they can be SENT — it is not a claim to stop injected inline script.
//
// connect-src is the one doing real work: even with script execution, exfiltrating a
// household's transaction history requires a request to somewhere, and this permits only this
// origin plus Plaid's Link iframe endpoints.
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.plaid.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' https://production.plaid.com https://sandbox.plaid.com",
  // Plaid Link runs in an iframe; nothing else may be embedded.
  "frame-src https://cdn.plaid.com",
  "object-src 'none'",
  "base-uri 'self'",
  // Belt and braces with X-Frame-Options above, for browsers that honour only one.
  "frame-ancestors 'none'",
  // No plain <form action> in this app — every mutation goes through fetch — so nothing
  // legitimate posts to another origin.
  "form-action 'self'",
].join('; ');

const nextConfig: NextConfig = {
  // Pruned server output (just the traced node_modules subset + server.js) instead of the
  // full node_modules tree, so the Docker runtime image (Dockerfile) stays small.
  output: 'standalone',

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [...securityHeaders, { key: 'Content-Security-Policy', value: csp }],
      },
    ];
  },
};

export default nextConfig;
