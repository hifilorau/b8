import { describe, it, expect } from 'vitest';
import { resolveAuthMode, requiresVerification, AuthConfigError, type AuthEnv } from './authConfig';

const CF: AuthEnv = { CF_ACCESS_TEAM_DOMAIN: 'household', CF_ACCESS_AUD: 'a'.repeat(64) };

describe('resolveAuthMode — the interlock', () => {
  // The failure this exists to prevent: adding a hostname to serve through a tunnel, forgetting
  // the identity variables, and silently publishing an app full of bank data with no login.
  it('refuses to start when a public host is allowed but Access is not configured', () => {
    expect(() => resolveAuthMode({ ALLOWED_HOSTS: 'finance.example.com' })).toThrow(AuthConfigError);
    expect(() => resolveAuthMode({ ALLOWED_HOSTS: 'finance.example.com' })).toThrow(/no authentication/i);
  });

  it('names the offending hosts so the error is actionable', () => {
    expect(() => resolveAuthMode({ ALLOWED_HOSTS: 'a.example.com,b.example.com' })).toThrow(
      /a\.example\.com, b\.example\.com/
    );
  });

  it('allows a public host once Access is configured', () => {
    const mode = resolveAuthMode({ ...CF, ALLOWED_HOSTS: 'finance.example.com' });
    expect(mode.kind).toBe('access');
  });

  it('stays in local mode when nothing is configured and nothing is exposed', () => {
    // Today's behaviour, and safe by construction rather than by trust: without ALLOWED_HOSTS
    // the host guard admits only loopback.
    expect(resolveAuthMode({}).kind).toBe('local');
    expect(resolveAuthMode({ ALLOWED_HOSTS: '' }).kind).toBe('local');
  });

  it('is not fooled by whitespace-only or comma-only ALLOWED_HOSTS', () => {
    expect(resolveAuthMode({ ALLOWED_HOSTS: '   ' }).kind).toBe('local');
    expect(resolveAuthMode({ ALLOWED_HOSTS: ',,,' }).kind).toBe('local');
  });
});

describe('resolveAuthMode — half-configured is always an error', () => {
  // Reads like protection while providing none, which is worse than plainly having none.
  it('rejects a team domain without an audience', () => {
    expect(() => resolveAuthMode({ CF_ACCESS_TEAM_DOMAIN: 'household' })).toThrow(/must be set together/);
  });

  it('rejects an audience without a team domain', () => {
    expect(() => resolveAuthMode({ CF_ACCESS_AUD: 'abc' })).toThrow(/must be set together/);
  });

  it('treats whitespace as unset rather than as a value', () => {
    expect(() => resolveAuthMode({ CF_ACCESS_TEAM_DOMAIN: '  ', CF_ACCESS_AUD: 'abc' })).toThrow(
      /must be set together/
    );
  });
});

describe('resolveAuthMode — dev bypass', () => {
  it('works outside production', () => {
    expect(resolveAuthMode({ AUTH_DEV_BYPASS: '1' }).kind).toBe('dev-bypass');
    expect(resolveAuthMode({ AUTH_DEV_BYPASS: '1', NODE_ENV: 'development' }).kind).toBe('dev-bypass');
  });

  it('refuses to start in production rather than silently ignoring itself', () => {
    // Silently ignoring it would be the worse failure: someone would believe the flag was
    // active and reason about the deployment on that basis.
    expect(() => resolveAuthMode({ AUTH_DEV_BYPASS: '1', NODE_ENV: 'production' })).toThrow(
      /will not activate in production/
    );
  });

  it('is opt-in by exact value, so a stray "0" or "false" does not disable auth', () => {
    expect(resolveAuthMode({ AUTH_DEV_BYPASS: '0' }).kind).toBe('local');
    expect(resolveAuthMode({ AUTH_DEV_BYPASS: 'false' }).kind).toBe('local');
    expect(resolveAuthMode({ AUTH_DEV_BYPASS: 'true' }).kind).toBe('local');
  });

  it('still rejects a half-configured Access setup even when bypassing', () => {
    // The bypass is about skipping verification, not about tolerating a broken config that
    // would fail the moment the flag came off.
    expect(() =>
      resolveAuthMode({ AUTH_DEV_BYPASS: '1', CF_ACCESS_TEAM_DOMAIN: 'household' })
    ).toThrow(/must be set together/);
  });
});

describe('requiresVerification', () => {
  it('is true only in access mode', () => {
    expect(requiresVerification(resolveAuthMode({ ...CF }))).toBe(true);
    expect(requiresVerification(resolveAuthMode({}))).toBe(false);
    expect(requiresVerification(resolveAuthMode({ AUTH_DEV_BYPASS: '1' }))).toBe(false);
  });
});
