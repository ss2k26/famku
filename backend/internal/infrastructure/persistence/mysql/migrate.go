// Package mysql implements the repositories on database/sql. The driver itself (github.com/go-sql-driver/mysql)
// is registered in cmd/server, so this package only depends on the standard library.
package mysql

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrate applies the pending migrations once, even when several replicas start together (named lock).
func Migrate(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx) // the lock belongs to one connection
	if err != nil {
		return err
	}
	defer conn.Close()
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK('famku_migrate', 60)").Scan(&got); err != nil || got.Int64 != 1 {
		return fmt.Errorf("migrate: could not take the migration lock: %v", err)
	}
	defer conn.ExecContext(context.Background(), "SELECT RELEASE_LOCK('famku_migrate')") //nolint:errcheck

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(64) NOT NULL PRIMARY KEY, applied_at DATETIME(6) NOT NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`); err != nil {
		return err
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		var exists int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		raw, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		for _, stmt := range splitStatements(string(raw)) {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migrate %s: %w", name, err)
			}
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", name, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

// splitStatements cuts a migration file at ";" line ends and drops "--" comment lines.
func splitStatements(src string) []string {
	var cur strings.Builder
	var out []string
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		cur.WriteString(line + "\n")
		if strings.HasSuffix(t, ";") {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}
