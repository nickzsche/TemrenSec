package database

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/temren/migrations"
)

// RunMigrations applies embedded migrations/*.sql in filename order, tracking
// applied files in a schema_migrations table so each file runs exactly once.
func RunMigrations(ctx context.Context) error {
	if Pool == nil {
		return fmt.Errorf("database pool is nil")
	}

	if _, err := Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		filename   TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	// Adopt a schema that was migrated manually before this runner existed:
	// if the users table is already present but schema_migrations is empty,
	// record every embedded migration as applied so 001 (plain CREATE TABLE)
	// doesn't error on an already-provisioned database.
	var count int
	if err := Pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		return fmt.Errorf("count schema_migrations: %w", err)
	}
	if count == 0 {
		var exists bool
		if err := Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users')`).Scan(&exists); err != nil {
			return fmt.Errorf("check users table: %w", err)
		}
		if exists {
			for _, name := range names {
				if _, err := Pool.Exec(ctx, `INSERT INTO schema_migrations (filename) VALUES ($1)`, name); err != nil {
					return fmt.Errorf("bootstrap %s: %w", name, err)
				}
			}
			log.Printf("[db] bootstrapped %d pre-existing migrations into schema_migrations", len(names))
			return nil
		}
	}

	for _, name := range names {
		var applied bool
		if err := Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE filename = $1)`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check %s: %w", name, err)
		}
		if applied {
			continue
		}

		sqlBytes, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}

		tx, err := Pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin %s: %w", name, err)
		}
		// Simple protocol runs the whole multi-statement file in one shot.
		if _, err := tx.Exec(ctx, string(sqlBytes), pgx.QueryExecModeSimpleProtocol); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (filename) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
		log.Printf("[db] applied migration %s", name)
	}

	return nil
}
