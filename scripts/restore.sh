#!/usr/bin/env bash
# Restores an encrypted backup produced by scripts/backup.sh into a TARGET database.
#
# Deliberately requires an explicit target rather than reading DATABASE_URL: the whole point of
# a restore drill is to rehearse against a scratch database, and defaulting to the live one
# makes the rehearsal itself the dangerous operation.
#
#   BACKUP_PASSPHRASE=... ./scripts/restore.sh <archive> <target-database-url>
#
# --clean drops objects before recreating them, so the target must be one you are happy to
# overwrite. The script refuses if the target already holds data, unless RESTORE_FORCE=1.

set -euo pipefail

: "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is not set}"

ARCHIVE="${1:?usage: restore.sh <archive> <target-database-url>}"
TARGET="${2:?usage: restore.sh <archive> <target-database-url>}"

[ -f "$ARCHIVE" ] || { echo "No such archive: $ARCHIVE" >&2; exit 1; }

# Refuse to overwrite a populated database by accident. `accounts` may legitimately not exist
# yet on a fresh target, which is the normal case for a drill.
EXISTING=$(psql "$TARGET" -tAc \
  "SELECT COALESCE((SELECT count(*) FROM accounts), 0)" 2>/dev/null || echo 0)
if [ "${EXISTING:-0}" -gt 0 ] && [ "${RESTORE_FORCE:-0}" != "1" ]; then
  echo "Target already has ${EXISTING} account(s). Refusing to overwrite; set RESTORE_FORCE=1 to proceed." >&2
  exit 1
fi

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -in "$ARCHIVE" \
  | pg_restore --clean --if-exists --no-owner --no-privileges --dbname "$TARGET"

echo "Restored ${ARCHIVE} into the target database."
echo "Verify before trusting it — scripts/verify-restore.mjs compares row counts and net worth."
