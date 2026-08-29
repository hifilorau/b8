import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { isAllowedHost, parseAllowedHosts } from '@/lib/hostGuard';
import { resolveAuthMode, requiresVerification } from '@/lib/authConfig';
import { verifyAccessAssertion } from '@/lib/accessJwt';
import { checkCsrf } from '@/lib/csrf';
import { VERIFIED_EMAIL_HEADER } from '@/lib/auth';
import { authorizeEmail } from '@/lib/users';
import { createLogger } from '@/lib/logger';

// Renamed from middleware.ts: the `middleware` file convention is deprecated in Next 16 and
// renamed to `proxy`. Same matcher semantics — only the file and export names changed.
//
// This is the single enforcement point for identity, and that is a deliberate choice over
// guarding each route. There are ~28 mutating handlers; gating them one by one means a new
// route added six months from now is unprotected until someone remembers, and nothing fails
// loudly when they don't. Here, a route cannot opt out of being covered.
//
// Order matters: host guard, then auth, then CSRF. The host guard first because everything
// downstream compares against the Host it establishes; CSRF last because it is only meaningful
// for a request that is already authenticated — an unauthenticated cross-site request should
// read as unauthenticated, which is the more useful thing to see in a log.

const log = createLogger('proxy');

// Resolved once at module scope. A misconfiguration throws HERE, at startup, rather than
// per-request — which is the entire point of the interlock in lib/authConfig.ts: an app that
// would serve financial data without authentication must fail to boot, not serve.
const AUTH_MODE = resolveAuthMode(process.env);
const ALLOWED_HOSTS = parseAllowedHosts(process.env.ALLOWED_HOSTS);

if (AUTH_MODE.kind === 'dev-bypass') {
  log.warn('AUTHENTICATION IS DISABLED (AUTH_DEV_BYPASS=1) — development only');
}

function isApiRequest(request: NextRequest): boolean {
  return request.nextUrl.pathname.startsWith('/api/');
}

/** Matches the ApiResponse contract in shared/types.ts, so API clients see one error shape. */
function deny(request: NextRequest, status: number, code: string, message: string): NextResponse {
  if (isApiRequest(request)) {
    return NextResponse.json({ success: false, error: { code, message } }, { status });
  }
  return new NextResponse(message, { status, headers: { 'content-type': 'text/plain' } });
}

export async function proxy(request: NextRequest) {
  if (!isAllowedHost(request.headers.get('host'), ALLOWED_HOSTS)) {
    return new NextResponse('Forbidden', { status: 403 });
  }

  // Cloned so the verified identity can be injected. Cloning also means the DELETE below
  // applies to what the app actually receives, not merely to a copy we then discard.
  const requestHeaders = new Headers(request.headers);

  // The security-critical line in this file. Without it, anyone could send
  // `x-b8-user-email: tom@example.com` and lib/auth.ts would believe it — the header is
  // trusted downstream precisely because it is overwritten here on every single request.
  // Deleted unconditionally, including in local and dev-bypass modes, so the header can never
  // mean anything except "the proxy verified this".
  requestHeaders.delete(VERIFIED_EMAIL_HEADER);

  if (requiresVerification(AUTH_MODE) && AUTH_MODE.kind === 'access') {
    try {
      const identity = await verifyAccessAssertion(
        request.headers.get('cf-access-jwt-assertion'),
        { teamDomain: AUTH_MODE.teamDomain, audience: AUTH_MODE.audience }
      );
      // Authentication is not authorization. Access says who this is; the users table says
      // whether they may see this household's finances. Enforced HERE rather than in pages
      // and routes because a test showed the alternative failing exactly as predicted: a
      // verified but unknown identity loaded /dashboard with a 200, since nothing on that
      // path happened to call requireUser(). One choke point, no route can forget.
      const user = await authorizeEmail(identity.email);
      if (!user) {
        log.warn('rejected a verified identity with no user record', {
          path: request.nextUrl.pathname,
        });
        return deny(
          request,
          403,
          'NOT_AUTHORIZED',
          'This identity is not permitted to use this application'
        );
      }

      requestHeaders.set(VERIFIED_EMAIL_HEADER, identity.email);
    } catch (err) {
      // Path but never the assertion itself: it is a bearer credential, and a log is a place
      // credentials leak from.
      log.warn('rejected an unverified request', {
        path: request.nextUrl.pathname,
        error: err instanceof Error ? err.message : String(err),
      });
      return deny(request, 401, 'UNAUTHENTICATED', 'Valid Cloudflare Access identity required');
    }
  }

  const csrf = checkCsrf({
    method: request.method,
    origin: request.headers.get('origin'),
    secFetchSite: request.headers.get('sec-fetch-site'),
    host: request.headers.get('host'),
  });
  if (!csrf.ok) {
    log.warn('rejected a cross-site state-changing request', {
      path: request.nextUrl.pathname,
      method: request.method,
      reason: csrf.reason,
    });
    return deny(request, 403, 'CROSS_SITE_REQUEST', 'Cross-site state-changing requests are refused');
  }

  // `request: { headers }` makes these visible to the app. Note NOT `NextResponse.next({ headers })`,
  // which would send them to the CLIENT instead — the Next docs call this trap out explicitly,
  // and here it would mean publishing the signed-in address in every response.
  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  // Excludes static assets so a rejected request still lets the browser fetch its own error
  // page's supporting files rather than compounding the failure; nothing here is a security
  // boundary the way the checks above are.
  //
  // Deliberately does NOT exclude page routes: the App Router addresses its RSC payload
  // requests to the page URL itself, so excluding them would leave a hole exactly the width
  // of the app's own data fetching.
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
