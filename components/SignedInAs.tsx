// Server component: reads the verified identity directly, so the signed-in address never has
// to be shipped to the client as props or fetched over an endpoint that would then need its
// own protection.
//
// Renders nothing in local and dev-bypass modes. There is no identity to show there, and a
// placeholder like "Local user" would suggest an authentication layer is doing something when
// it is not — the one impression this component must not create.

import { getCurrentUser } from '@/lib/auth';
import { resolveAuthMode } from '@/lib/authConfig';

export default async function SignedInAs() {
  const mode = resolveAuthMode(process.env);
  if (mode.kind !== 'access') return null;

  const user = await getCurrentUser();
  if (!user) return null;

  return (
    <div className="px-3 pb-5">
      <div className="border-t border-slate-800 mb-3" />
      <div className="px-3">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-600">
          Signed in
        </p>
        <p className="mt-1 text-xs text-slate-300 truncate" title={user.email}>
          {user.displayName ?? user.email}
        </p>
        {/* Cloudflare owns the session, so signing out means clearing ITS cookie. A local
            control would only log you out of an app that re-authenticates on the next
            request, which would look broken. */}
        <a
          href="/cdn-cgi/access/logout"
          className="mt-2 inline-block text-xs text-slate-500 hover:text-slate-300 transition-colors"
        >
          Sign out
        </a>
      </div>
    </div>
  );
}
