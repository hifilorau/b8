import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { isAllowedHost, parseAllowedHosts } from '@/lib/hostGuard';

// Renamed from middleware.ts: the `middleware` file convention is deprecated in Next 16 and
// renamed to `proxy` (node_modules/next/dist/docs/01-app/03-api-reference/03-file-conventions/
// middleware.md). Same functionality, same matcher semantics — only the file and export names
// changed.
//
// A bare stopgap ahead of real auth (ROADMAP.md §3): this app is single-user, zero-auth,
// and syncs real bank accounts. The dev/start scripts already bind to 127.0.0.1 only, so
// this exists to close the DNS-rebinding gap that network binding alone doesn't — see
// lib/hostGuard.ts for why a same-machine attacker can still reach a 127.0.0.1-bound server
// with an attacker-controlled Host header despite that binding.
//
// Read at module scope, not per-request: the value cannot change without a restart, and the
// proxy runs on every request. Note that a Host allowlist stops being an authorization
// boundary the moment ALLOWED_HOSTS names a public hostname — see lib/hostGuard.ts.
const ALLOWED_HOSTS = parseAllowedHosts(process.env.ALLOWED_HOSTS);

export function proxy(request: NextRequest) {
  if (!isAllowedHost(request.headers.get('host'), ALLOWED_HOSTS)) {
    return new NextResponse('Forbidden', { status: 403 });
  }
  return NextResponse.next();
}

export const config = {
  // Excludes static assets so a rejected Host still lets the browser fetch its own error
  // page's supporting files rather than compounding the failure; nothing here is a security
  // boundary the way the route match above is.
  //
  // Deliberately does NOT exclude page routes: the App Router addresses its RSC payload
  // requests to the page URL itself, so excluding them would leave a hole exactly the width
  // of the app's own data fetching.
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
