package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationLockID is an arbitrary but stable key for the Postgres advisory lock
// that serialises migration runs. API and worker containers start together and
// k8s runs the API with replicaCount > 1, so without this several processes
// would race to apply 001_init.sql at the same instant.
const migrationLockID int64 = 8_014_252_119_001

// MigrationsDir resolves where the .sql files live: MIGRATIONS_DIR wins, then
// ./migrations (the container WORKDIR layout), then /app/migrations.
func MigrationsDir() string {
	if dir := os.Getenv("MIGRATIONS_DIR"); dir != "" {
		return dir
	}
	for _, candidate := range []string{"migrations", "/app/migrations"} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return "migrations"
}

// RunMigrations applies every not-yet-applied .sql file in dir, in filename
// order, each inside its own transaction. Applied versions are recorded in
// schema_migrations, so files need not be individually idempotent.
//
// This is called on API and worker startup. Before it existed the migrations
// directory shipped in the image and was mounted by docker-compose, but nothing
// ever executed it — every deployment came up against an empty schema.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	files, err := migrationFiles(dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		log.Printf("[migrate] no migration files found in %s", dir)
		return nil
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	// Block until any peer finishes; the lock is released when we return it.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLockID); err != nil {
			log.Printf("[migrate] releasing advisory lock: %v", err)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			checksum   TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[string]string{}
	rows, err := conn.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			rows.Close()
			return fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[version] = checksum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}

	ran := 0
	for _, file := range files {
		version := filepath.Base(file)

		body, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read %s: %w", version, err)
		}
		sum := sha256.Sum256(body)
		checksum := hex.EncodeToString(sum[:])

		if prev, ok := applied[version]; ok {
			// Editing an applied migration silently diverges environments —
			// warn loudly rather than trying to reconcile it.
			if prev != checksum {
				log.Printf("[migrate] WARNING: %s already applied but its contents changed "+
					"(recorded %s, on disk %s); add a new migration instead of editing this one",
					version, prev[:12], checksum[:12])
			}
			continue
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`,
			version, checksum); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", version, err)
		}

		log.Printf("[migrate] applied %s", version)
		ran++
	}

	if ran == 0 {
		log.Printf("[migrate] schema up to date (%d migrations already applied)", len(applied))
	} else {
		log.Printf("[migrate] applied %d migration(s)", ran)
	}
	return nil
}

func migrationFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("migrations directory %q not found (set MIGRATIONS_DIR)", dir)
		}
		return nil, fmt.Errorf("read migrations directory %q: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	// Filenames are zero-padded (001_, 002_, ...), so lexical order is apply order.
	sort.Strings(files)
	return files, nil
}
