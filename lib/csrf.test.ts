import { describe, it, expect } from 'vitest';
import { checkCsrf } from './csrf';

const req = (over: Partial<Parameters<typeof checkCsrf>[0]> = {}) => ({
  method: 'POST',
  origin: null,
  secFetchSite: null,
  host: 'finance.example.com',
  ...over,
});

describe('checkCsrf — safe methods', () => {
  it('never blocks a read', () => {
    for (const method of ['GET', 'HEAD', 'OPTIONS', 'get']) {
      expect(checkCsrf(req({ method, secFetchSite: 'cross-site', origin: 'https://evil.example' })).ok).toBe(true);
    }
  });
});

describe('checkCsrf — the attack it exists for', () => {
  // Access authenticates with a cookie, so a POST from a hostile page arrives already
  // authenticated. Access can say "this is Tom"; it cannot say "Tom meant to do this".
  it('blocks a cross-site mutation', () => {
    const v = checkCsrf(req({ secFetchSite: 'cross-site' }));
    expect(v.ok).toBe(false);
    expect(v).toMatchObject({ reason: expect.stringContaining('cross-site') });
  });

  it('blocks a same-site mutation from a neighbouring subdomain', () => {
    // A household running several apps under one domain: the neighbour must not write here.
    expect(checkCsrf(req({ secFetchSite: 'same-site' })).ok).toBe(false);
  });

  it('blocks a mutation whose Origin disagrees with the Host', () => {
    expect(checkCsrf(req({ origin: 'https://evil.example' })).ok).toBe(false);
  });

  it('treats a different port as a different origin', () => {
    expect(
      checkCsrf(req({ host: 'localhost:3000', origin: 'http://localhost:3001' })).ok
    ).toBe(false);
  });

  it('blocks an unparseable Origin rather than ignoring it', () => {
    expect(checkCsrf(req({ origin: 'not a url' })).ok).toBe(false);
  });
});

describe('checkCsrf — legitimate traffic', () => {
  it('allows a same-origin mutation', () => {
    expect(checkCsrf(req({ secFetchSite: 'same-origin', origin: 'https://finance.example.com' })).ok).toBe(true);
  });

  it('allows the app’s own fetch calls, which send a matching Origin', () => {
    expect(checkCsrf(req({ host: 'localhost:3000', origin: 'http://localhost:3000' })).ok).toBe(true);
  });

  it('is case-insensitive on the host comparison', () => {
    expect(checkCsrf(req({ host: 'Finance.Example.COM', origin: 'https://finance.example.com' })).ok).toBe(true);
  });

  it('allows a non-browser client that sends neither header', () => {
    // Deliberate: absence means no ambient cookie jar to spend, so there is no confused deputy
    // to protect against. Rejecting here would break curl and health checks for no gain.
    expect(checkCsrf(req()).ok).toBe(true);
  });

  it('allows Sec-Fetch-Site: none, which is a user-initiated navigation', () => {
    expect(checkCsrf(req({ secFetchSite: 'none' })).ok).toBe(true);
  });

  it('allows an opaque "null" Origin when the site relationship is not cross-site', () => {
    expect(checkCsrf(req({ origin: 'null', secFetchSite: 'same-origin' })).ok).toBe(true);
  });

  it('still blocks an opaque Origin when the browser says cross-site', () => {
    // A sandboxed iframe sends Origin: null; Sec-Fetch-Site is what actually settles it.
    expect(checkCsrf(req({ origin: 'null', secFetchSite: 'cross-site' })).ok).toBe(false);
  });
});
