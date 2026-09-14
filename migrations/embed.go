// Package migrations embeds the SQL migration files so the database package
// can apply them automatically at startup.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
