#!/usr/bin/env sh
set -eu

DB_PATH=${DATABASE_PATH:-/data/sentinel.db}
DB_DIR=$(dirname "${DB_PATH}")

mkdir -p "${DB_DIR}"

if [ ! -f "${DB_PATH}" ]; then
  echo "Database not found, creating ${DB_PATH}"
  sqlite3 "${DB_PATH}" "PRAGMA user_version;" >/dev/null
fi

echo "Applying migrations to ${DB_PATH}"

for file in internal/storage/migrations/*.sql; do
  echo "Running ${file}"
  sqlite3 "${DB_PATH}" < "${file}"
done

echo "Done"
