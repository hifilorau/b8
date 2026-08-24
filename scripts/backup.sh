#!/usr/bin/env bash
# Encrypted PostgreSQL backup.
#
# The threat this exists for is mundane: the machine dies, or the disk does. Losing this
# database costs more than re-linking banks. Transactions can be re-synced from Plaid, but
# every manual valuation, every hand-assigned category, every property cost basis and the whole
# net_worth_snapshots series exist ONLY here — snapshots especially, since they record how net
# worth was computed on a date and cannot be recomputed after an account is reclassified.
#
# Backups are encrypted because an unencrypted dump is the thing token-at-rest encryption was
# meant to stop being catastrophic. Note the pairing rule: this is encrypted with BACKUP_PASSPHRASE,
# NOT with TOKEN_ENCRYPTION_KEY. Restoring needs both — the passphrase to open the archive, and
# the token key to use the Plaid credentials inside it. Store them separately from each other and
# from the backups, or you have re-created the single point of failure.
#
#   BACKUP_PASSPHRASE=... DATABASE_URL=... ./scripts/backup.sh [output-dir]
#
# Restore with scripts/restore.sh. A backup nobody has restored is a hypothesis, not a backup.

set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is not set}"
: "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is not set — refusing to write an unencrypted backup}"

OUT_DIR="${1:-./backups}"
RETAIN="${BACKUP_RETAIN:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$OUT_DIR"

# The timestamp is only second-resolution, so two runs in the same second would otherwise land
# on one filename and the second would silently overwrite the first. Unlikely on a daily
# schedule, but a manual backup taken right after a scheduled one is exactly the case where
# losing the earlier archive would matter, so never reuse a name.
ARCHIVE="${OUT_DIR}/b8-${STAMP}.dump.enc"
SUFFIX=1
while [ -e "$ARCHIVE" ]; do
  ARCHIVE="${OUT_DIR}/b8-${STAMP}-${SUFFIX}.dump.enc"
  SUFFIX=$((SUFFIX + 1))
done

# -Fc: pg_restore's custom format, so a restore can be selective and parallel.
# Piped straight into openssl so the plaintext dump never touches the disk.
# pbkdf2 with an explicit iteration count: the passphrase is human-chosen, so the KDF is the
# only thing standing between a leaked archive and an offline guessing attack.
pg_dump --format=custom --no-owner --no-privileges "$DATABASE_URL" \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:BACKUP_PASSPHRASE \
  > "$ARCHIVE"

chmod 600 "$ARCHIVE"

# A zero-byte or truncated archive is worse than none, because it looks like success in a
# directory listing. Fail loudly now rather than at restore time.
SIZE=$(wc -c < "$ARCHIVE")
if [ "$SIZE" -lt 1024 ]; then
  echo "Backup is implausibly small (${SIZE} bytes) — treating as failed" >&2
  rm -f "$ARCHIVE"
  exit 1
fi

# Pruned only AFTER the new archive is confirmed non-trivial, so a failing backup job can never
# delete the last good one.
DELETED=0
if [ "$RETAIN" -gt 0 ]; then
  while IFS= read -r old; do
    rm -f "$old"
    DELETED=$((DELETED + 1))
  done < <(ls -1t "${OUT_DIR}"/b8-*.dump.enc 2>/dev/null | tail -n "+$((RETAIN + 1))")
fi

echo "Wrote ${ARCHIVE} ($(numfmt --to=iec "$SIZE" 2>/dev/null || echo "${SIZE}B")); pruned ${DELETED} old backup(s), keeping ${RETAIN}."
