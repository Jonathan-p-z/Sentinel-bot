#!/usr/bin/env sh
set -eu

DB_PATH=${DATABASE_PATH:-/data/sentinel.db}

echo "Applying migrations to ${DB_PATH}"

for file in internal/storage/migrations/*.sql; do
  echo "Running ${file}"
  sqlite3 "${DB_PATH}" < "${file}"
done

echo "Done"
