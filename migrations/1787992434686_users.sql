-- Up Migration

-- Who is allowed to use this app, as distinct from who Cloudflare Access will let through.
--
-- Those are deliberately two different questions. Access decides whether a person may reach
-- the origin; this table decides whether they may see the household's finances. Keeping them
-- separate buys two things: a revocation path that takes effect immediately and locally,
-- without waiting on a Cloudflare policy change, and a second line of defence if an Access
-- policy is ever mis-scoped (say, widened to a whole email domain by accident). An identity
-- that passes Access but is absent here is refused.
--
-- No password column, and there will not be one. Access is the identity provider; storing
-- credentials again here would add a second thing to leak and a second thing to get wrong,
-- for no benefit.
CREATE TABLE users (
  id            SERIAL PRIMARY KEY,
  -- Lowercased on write. Postgres comparison is case-sensitive by default, so without
  -- normalising, Tom@example.com and tom@example.com would be two different people.
  email         TEXT NOT NULL UNIQUE,
  display_name  TEXT,
  -- One role for now. Present because adding a column later to a table that gates access is
  -- more disruptive than carrying an honest default from the start; the app does not branch
  -- on it yet.
  role          TEXT NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'member')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Refreshed on each verified request. The cheapest possible answer to "is this account
  -- still being used, and by whom" when it comes time to prune access.
  last_seen_at  TIMESTAMPTZ
);

-- Down Migration

DROP TABLE IF EXISTS users;
