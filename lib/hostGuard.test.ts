import { describe, it, expect } from 'vitest';
import { isAllowedHost, parseAllowedHosts } from './hostGuard';

describe('isAllowedHost', () => {
  it('allows the hostnames the dev/start scripts actually serve on', () => {
    expect(isAllowedHost('localhost:3000')).toBe(true);
    expect(isAllowedHost('127.0.0.1:3000')).toBe(true);
  });

  it('allows those hostnames with no port', () => {
    expect(isAllowedHost('localhost')).toBe(true);
    expect(isAllowedHost('127.0.0.1')).toBe(true);
  });

  it('is case-insensitive on the hostname', () => {
    expect(isAllowedHost('LOCALHOST:3000')).toBe(true);
  });

  it('allows the IPv6 loopback literal, bracketed with a port', () => {
    expect(isAllowedHost('[::1]:3000')).toBe(true);
    expect(isAllowedHost('[::1]')).toBe(true);
  });

  it('rejects a spoofed Host header — the DNS-rebinding case this exists for', () => {
    expect(isAllowedHost('evil.com')).toBe(false);
    expect(isAllowedHost('evil.com:3000')).toBe(false);
  });

  it('rejects a Tailscale/VPN hostname that is not yet in the allowlist', () => {
    // Deliberately strict: the AWS/Tailscale deployment track (ROADMAP.md §2) will need to
    // extend this allowlist explicitly, not fall through by accident.
    expect(isAllowedHost('my-tailnet-host.ts.net:3000')).toBe(false);
  });

  it('rejects null and empty Host headers', () => {
    expect(isAllowedHost(null)).toBe(false);
    expect(isAllowedHost('')).toBe(false);
  });

  it('does not mistake an IPv6 literal’s internal colons for the port separator', () => {
    // A pathological host string with no brackets would misparse under naive `split(':')`.
    expect(isAllowedHost('::1:3000')).toBe(false);
  });

  it('rejects a hostname that merely contains an allowed one as a substring', () => {
    expect(isAllowedHost('localhost.evil.com')).toBe(false);
    expect(isAllowedHost('notlocalhost:3000')).toBe(false);
  });
});

describe('isAllowedHost — configured extra hosts', () => {
  // A Cloudflare Tunnel forwards the ORIGINAL public Host, so without this the tunnel 403s
  // every request. The tests below are the contract that makes that configurable safely.
  const configured = ['finance.example.com'];

  it('allows a configured public hostname, with and without a port', () => {
    expect(isAllowedHost('finance.example.com', configured)).toBe(true);
    expect(isAllowedHost('finance.example.com:443', configured)).toBe(true);
  });

  it('still rejects a host that was not configured', () => {
    expect(isAllowedHost('evil.com', configured)).toBe(false);
    expect(isAllowedHost('finance.example.com.evil.com', configured)).toBe(false);
  });

  it('keeps loopback working when extra hosts are configured', () => {
    // Local access is the documented way back in when a tunnel or IdP is what broke, so
    // configuring a public hostname must never cost it.
    expect(isAllowedHost('localhost:3000', configured)).toBe(true);
  });

  it('keeps loopback working when nothing is configured', () => {
    expect(isAllowedHost('localhost:3000', [])).toBe(true);
    expect(isAllowedHost('evil.com', [])).toBe(false);
  });

  it('is case-insensitive on a configured hostname', () => {
    expect(isAllowedHost('FINANCE.EXAMPLE.COM', configured)).toBe(true);
    expect(isAllowedHost('finance.example.com', ['FINANCE.EXAMPLE.COM'])).toBe(true);
  });
});

describe('parseAllowedHosts', () => {
  it('returns nothing for unset, empty, or whitespace-only values', () => {
    // The common case: local-only use, where the allowlist stays loopback-only.
    expect(parseAllowedHosts(undefined)).toEqual([]);
    expect(parseAllowedHosts(null)).toEqual([]);
    expect(parseAllowedHosts('')).toEqual([]);
    expect(parseAllowedHosts('   ')).toEqual([]);
  });

  it('splits on commas and trims surrounding whitespace', () => {
    expect(parseAllowedHosts('a.example.com, b.example.com')).toEqual([
      'a.example.com',
      'b.example.com',
    ]);
  });

  it('drops empty entries from trailing or doubled commas', () => {
    expect(parseAllowedHosts('a.example.com,,b.example.com,')).toEqual([
      'a.example.com',
      'b.example.com',
    ]);
  });

  it('normalizes a configured entry written with a port', () => {
    // Otherwise a value copied from a browser URL bar would silently never match a request
    // that arrives without the port.
    expect(parseAllowedHosts('finance.example.com:443')).toEqual(['finance.example.com']);
  });

  it('lowercases entries', () => {
    expect(parseAllowedHosts('Finance.Example.COM')).toEqual(['finance.example.com']);
  });
});
