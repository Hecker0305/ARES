#!/bin/bash
# migrate.sh - Database migration runner for ARES Engine
# Usage: ./migrate.sh [up|down|status] [migration_number]

set -euo pipefail

DB_URL="${ARES_MEMORY_DSN:-postgres://localhost:5432/ares?sslmode=verify-full}"
MIGRATIONS_DIR="$(cd "$(dirname "$0")" && pwd)"

command -v psql >/dev/null 2>&1 || { echo "Error: psql is required but not installed"; exit 1; }

extract_db_url() {
  echo "$DB_URL" | sed 's|file://.*||'
}

run_migration() {
  local file="$1"
  local direction="$2"

  if [ ! -f "$file" ]; then
    echo "Error: Migration file not found: $file"
    exit 1
  fi

  echo "Running migration: $(basename "$file") [$direction]"

  if [ "$direction" = "up" ]; then
    psql "$DB_URL" -1 -f "$file"
  else
    echo "Down migrations not yet implemented for: $(basename "$file")"
  fi
}

migrate_up() {
  local target="${1:-}"

  for migration in "$MIGRATIONS_DIR"/*.sql; do
    local num=$(basename "$migration" | cut -d'_' -f1)

    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
      echo "Warning: Skipping non-numeric migration prefix: $num"
      continue
    fi

    if [ -n "$target" ] && [ "$num" -gt "$target" ]; then
      break
    fi

    run_migration "$migration" "up"
  done

  echo "All migrations applied successfully"
}

migrate_down() {
  local target="${1:?Target migration number required}"

  echo "Rolling back to migration: $target"
  echo "Note: Individual down migrations need to be implemented"
}

show_status() {
  echo "Migration status:"
  echo "================"

  for migration in "$MIGRATIONS_DIR"/*.sql; do
    local name=$(basename "$migration")
    local num=$(echo "$name" | cut -d'_' -f1)
    local desc=$(echo "$name" | sed 's/^[0-9]*_//' | sed 's/\.sql$//')

    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
      echo "  [SKIP]     $name (non-numeric prefix)"
      continue
    fi

    local applied=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM pg_tables WHERE tablename = 'schema_migrations';" 2>/dev/null || echo "0")
    applied=$(echo "$applied" | tr -d '[:space:]')

    if [ "$applied" -gt 0 ] 2>/dev/null; then
      local is_applied=$(psql "$DB_URL" -t -c "SELECT COUNT(*) FROM schema_migrations WHERE version = $num;" 2>/dev/null || echo "0")
      is_applied=$(echo "$is_applied" | tr -d '[:space:]')
      if [ "$is_applied" -gt 0 ] 2>/dev/null; then
        echo "  [APPLIED]  $name"
      else
        echo "  [PENDING]  $name"
      fi
    else
      echo "  [UNKNOWN]  $name (schema_migrations table not found)"
    fi
  done
}

case "${1:-help}" in
  up)
    migrate_up "${2:-}"
    ;;
  down)
    migrate_down "${2:-}"
    ;;
  status)
    show_status
    ;;
  help|*)
    echo "Usage: $0 {up|down|status} [migration_number]"
    echo ""
    echo "Commands:"
    echo "  up [N]      Apply all migrations up to N (or all if not specified)"
    echo "  down N      Roll back to migration N"
    echo "  status      Show migration status"
    echo ""
    echo "Environment:"
    echo "  ARES_MEMORY_DSN  PostgreSQL connection string (sslmode=verify-full by default)"
    ;;
esac
