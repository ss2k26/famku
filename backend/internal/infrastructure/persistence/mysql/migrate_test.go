package mysql

import (
	"strings"
	"testing"
)

func TestSplitStatements(t *testing.T) {
	src := "-- comment\nCREATE TABLE a (\n  id INT\n);\n\n-- more\nCREATE TABLE b (id INT);\n"
	got := splitStatements(src)
	if len(got) != 2 || !strings.HasPrefix(got[0], "CREATE TABLE a") || !strings.HasPrefix(got[1], "CREATE TABLE b") {
		t.Fatalf("unexpected split: %q", got)
	}
}

func TestEmbeddedMigrationsSplitCleanly(t *testing.T) {
	raw, err := migrationFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	stmts := splitStatements(string(raw))
	if len(stmts) != 5 {
		t.Fatalf("want 5 CREATE TABLE statements, got %d", len(stmts))
	}
	for _, s := range stmts {
		if !strings.HasPrefix(s, "CREATE TABLE") || !strings.HasSuffix(s, ";") {
			t.Fatalf("bad statement: %q", s)
		}
	}
}

func TestUsernameMigrationSplitsCleanly(t *testing.T) {
	raw, err := migrationFS.ReadFile("migrations/0002_username.sql")
	if err != nil {
		t.Fatal(err)
	}
	stmts := splitStatements(string(raw))
	if len(stmts) != 3 || !strings.HasPrefix(stmts[0], "ALTER TABLE users ADD COLUMN username") ||
		!strings.HasPrefix(stmts[1], "UPDATE users") || !strings.Contains(stmts[2], "uq_users_username") {
		t.Fatalf("unexpected statements: %q", stmts)
	}
}

func TestDuplicateDetection(t *testing.T) {
	if !isDuplicate(errString("Error 1062 (23000): Duplicate entry 'x' for key 'uq_users_email'")) || isDuplicate(nil) {
		t.Fatal("duplicate detection broken")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
