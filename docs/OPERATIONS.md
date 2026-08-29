# Operations

Backup, restore, and the checks worth passing before real bank credentials go anywhere near
this app.

## Why backups matter more than they look

Transactions can be re-pulled from Plaid. Almost nothing else can:

- **Manual valuations** — every property value and every hand-entered account balance.
- **Categorisation** — every transaction you re-categorised by hand, every rule, every
  transfer group, every hidden flag.
- **Property basis** — purchase price and cost basis, including capital improvements.
- **`net_worth_snapshots`** — the worst case. Each row records what net worth *was* on a date,
  under the account classifications in force that day. It cannot be recomputed later: change an
  account's valuation mode or delete one and the history would silently rewrite itself. That is
  why it is stored rather than derived, and why losing it loses the series permanently.

Re-linking banks after a disaster is an afternoon. Reconstructing the above is not possible.

## Taking a backup

```sh
BACKUP_PASSPHRASE=... DATABASE_URL=... ./scripts/backup.sh ./backups
```

`pg_dump` piped straight into `openssl enc -aes-256-cbc -pbkdf2 -iter 200000`, so the plaintext
dump never touches the disk. Refuses to run without a passphrase rather than quietly writing an
unencrypted archive. `BACKUP_RETAIN` (default 14) prunes older archives — but only *after* the
new one is confirmed non-trivial, so a failing backup can never delete the last good one.

### Two secrets, stored apart

Restoring needs both, and they protect against different things:

| Secret | Opens | Losing it means |
|---|---|---|
| `BACKUP_PASSPHRASE` | the archive | backups are unreadable |
| `TOKEN_ENCRYPTION_KEY` | Plaid tokens *inside* it | re-link every institution |

Keep them apart from each other and from the backups. A passphrase stored beside the archives,
or a token key inside a database backup, re-creates the single point of failure both exist to
remove.

## Restoring

```sh
BACKUP_PASSPHRASE=... ./scripts/restore.sh ./backups/b8-<stamp>.dump.enc "$TARGET_URL"
```

The target is an explicit argument, never `DATABASE_URL`, because the common use of this script
is a rehearsal and a rehearsal that defaults to the live database is the dangerous kind. It
refuses a target that already holds accounts unless `RESTORE_FORCE=1`.

## The drill — the part that is actually the deliverable

A backup nobody has restored is a hypothesis. Run this end to end, on a schedule:

```sh
createdb b8_restore_test
BACKUP_PASSPHRASE=... ./scripts/restore.sh ./backups/b8-<stamp>.dump.enc \
  postgresql://localhost/b8_restore_test

TOKEN_ENCRYPTION_KEY=... node scripts/verify-restore.mjs \
  "$DATABASE_URL" postgresql://localhost/b8_restore_test

dropdb b8_restore_test
```

`verify-restore.mjs` exits non-zero on any mismatch — which is the point, because it turns "we
have backups" into something a cron job can assert. It compares three things:

1. **Row counts** for every table.
2. **Net worth**, recomputed on both sides with the same rule as `lib/domain/netWorth.ts`,
   required to match to the cent.
3. **Value checksums** over every numeric column anyone reads.

The third is not redundant, and it was added after the first version of this drill passed a
database it should have failed. Net worth reads only the *latest* valuation per account, so
altering a historical `account_valuations` row corrupts the equity chart and every past
snapshot while leaving today's figure identical — invisible to both row counts and a
net-worth comparison. Summing the value columns closes that gap.

It also decrypts every restored Plaid credential. A restore that comes back with unreadable
tokens looks perfect by row count and leaves you re-linking every bank by hand.

## Release gate — before connecting production Plaid credentials

- [x] Plaid Items modelled explicitly; one token and one cursor per connection.
- [x] Access tokens encrypted at rest; a database dump alone yields nothing usable.
- [x] Encrypted backups, with retention that cannot delete the last good archive.
- [x] Restore tested end to end and verified against the source, not assumed.
- [x] Migrations exercised against seeded data in CI, not just an empty database.
- [x] A repeated sync does not duplicate transactions (`plaid_transaction_id` upsert plus
      re-identification of reissued ids — `lib/domain/txnMatch.ts`).
- [x] Reconnect preserves history (`lib/plaidMatch.ts`, five-pass account matching).
- [x] **Application authentication.** Cloudflare Access assertions are verified at the origin,
      with issuer and audience pinned; a verified identity must additionally have a row in
      `users`. `ALLOWED_HOSTS` naming a public host without Access configured is a startup
      error, so the app cannot be exposed without a login by forgetting a variable.
- [ ] Off-machine copy of the backups. `scripts/backup.sh` writes locally; copying archives to
      a second machine or object store is not automated yet, and a backup on the same disk as
      the database does not survive the failure it exists for.
- [ ] `TOKEN_ENCRYPTION_KEY` and `BACKUP_PASSPHRASE` recorded somewhere durable and separate
      from the machine — a password manager, not a file beside the backups.

## Note on `PLAID_ENV`

`sandbox` by default. Setting it to `production` is what makes every credential in this system
real. Do the unchecked items above first.
