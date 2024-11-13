// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/dbtxn"

	_ "github.com/jackc/pgx/v4/stdlib"
)

func CreateTestPGUser(t *testing.T, connURL string, username, password, query string) {
	t.Helper()
	t.Logf("[TRACE] Creating test user")

	db, err := sql.Open("pgx", connURL)
	defer db.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Start a transaction
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	m := map[string]string{
		"name":     username,
		"password": password,
	}
	if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
		t.Fatal(err)
	}
	// Commit the transaction
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
