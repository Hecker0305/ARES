package db

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"

	"github.com/ares/engine/internal/logger"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const schemaVersion = 4

func Init(dbPath string) (*sql.DB, error) {
	if dbPath == "" {
		dbPath = os.Getenv("ARES_DB_PATH")
	}
	if dbPath == "" {
		dbPath = os.Getenv("ARES_DATABASE_URL")
	}

	if dbPath != "" && strings.HasPrefix(dbPath, "postgres://") {
		return initPostgreSQL(dbPath)
	}

	if dbPath == "" {
		dataDir := os.Getenv("ARES_DATA_DIR")
		if dataDir == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				dataDir = "/tmp/.ares"
			} else {
				dataDir = filepath.Join(homeDir, ".ares")
			}
		}
		os.MkdirAll(dataDir, 0700)
		dbPath = filepath.Join(dataDir, "ares.db")
	}

	dir := filepath.Dir(dbPath)
	os.MkdirAll(dir, 0700)

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(4)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	logger.Info("[DB] Connected to SQLite at %s", logger.Fields{"path": dbPath})

	if err := RunMigrations(db, "sqlite"); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return db, nil
}

func initPostgreSQL(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres db: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(60 * 60)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres db: %w", err)
	}

	logger.Info("[DB] Connected to PostgreSQL")

	if err := RunMigrations(db, "postgres"); err != nil {
		return nil, fmt.Errorf("run postgres migrations: %w", err)
	}

	return db, nil
}

func RunMigrations(db *sql.DB, dbType string) error {
	var version int
	var err error

	if dbType == "postgres" {
		err = db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
		if err != nil {
			if strings.Contains(err.Error(), "does not exist") {
				if _, err := db.Exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"); err != nil {
					return fmt.Errorf("create migrations table: %w", err)
				}
				version = 0
			} else {
				return fmt.Errorf("check migration version: %w", err)
			}
		}
	} else {
		err = db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
		if err != nil {
			if !strings.Contains(err.Error(), "no such table") {
				return fmt.Errorf("check migration version: %w", err)
			}
			if _, err := db.Exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"); err != nil {
				return fmt.Errorf("create migrations table: %w", err)
			}
			version = 0
		}
	}

	for i := version + 1; i <= schemaVersion; i++ {
		filename := fmt.Sprintf("migrations/%03d_initial_schema.sql", i)
		if i == 2 {
			filename = "migrations/%03d_add_tenants.sql"
		} else if i == 3 {
			filename = "migrations/%03d_add_schedules_and_webhooks.sql"
		} else if i == 4 {
			filename = "migrations/%03d_add_new_features.sql"
		}

		content, err := migrationFS.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("read migration %d: %w", i, err)
		}

		logger.Info("[DB] Running migration %d", logger.Fields{"version": i})

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}

		stmts := strings.Split(string(content), ";")
		for _, stmt := range stmts {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" || strings.HasPrefix(stmt, "--") {
				continue
			}
			if dbType == "postgres" {
				stmt = strings.ReplaceAll(stmt, "INTEGER PRIMARY KEY", "SERIAL PRIMARY KEY")
				stmt = strings.ReplaceAll(stmt, "AUTOINCREMENT", "")
				stmt = strings.ReplaceAll(stmt, "DATETIME", "TIMESTAMP")
				stmt = strings.ReplaceAll(stmt, "TEXT", "VARCHAR")
			}
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration %d stmt: %w", i, err)
			}
		}

		if dbType == "postgres" {
			if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", i); err != nil {
				tx.Rollback()
				return fmt.Errorf("record migration %d: %w", i, err)
			}
		} else {
			if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", i); err != nil {
				tx.Rollback()
				return fmt.Errorf("record migration %d: %w", i, err)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", i, err)
		}
	}

	if version > 0 {
		logger.Info("[DB] Schema up to date (version %d)", logger.Fields{"version": version})
	}

	return nil
}
