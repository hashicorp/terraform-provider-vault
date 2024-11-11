// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/dbtxn"
	"github.com/hashicorp/vault/sdk/helper/docker"

	_ "github.com/jackc/pgx/v4/stdlib"
)

const (
	defaultPGImage   = "docker.mirror.hashicorp.services/postgres"
	defaultPGVersion = "13.4-buster"
	defaultPGPass    = "secret"
)

func defaultRunOpts(t *testing.T) docker.RunOptions {
	return docker.RunOptions{
		ContainerName: "postgres",
		ImageRepo:     defaultPGImage,
		ImageTag:      defaultPGVersion,
		Env: []string{
			"POSTGRES_PASSWORD=" + defaultPGPass,
			"POSTGRES_DB=database",
		},
		Ports:             []string{"5432/tcp"},
		DoNotAutoRemove:   false,
		OmitLogTimestamps: true,
		LogConsumer: func(s string) {
			t.Logf("container logs: %s", s)
		},
	}
}

func GetTestPGUser(t *testing.T, connURL string, username, password, query string) {
	t.Helper()
	t.Logf("[TRACE] Creating test user")

	db, err := sql.Open("pgx", connURL)
	defer db.Close()
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_, err = db.ExecContext(ctx, `SELECT set_config('log_statement', 'all', false);`)
	if err != nil {
		t.Fatal(err)
	}

	var exists bool
	err = db.QueryRowContext(ctx, "SELECT exists (SELECT rolname FROM pg_roles WHERE rolname=$1);", username).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("user does not appear to exist: %w", err)
	}
	if !exists {
		t.Fatalf("!exists: %w", err)
	}
	t.Logf("exists: %b", exists)
}

func CreateTestPGUser(t *testing.T, connURL string, username, password, query string) {
	t.Helper()
	t.Logf("[TRACE] Creating test user")

	db, err := sql.Open("pgx", connURL)
	defer db.Close()
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.ExecContext(context.Background(), `SELECT set_config('log_statement', 'all', false);`)
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

func PrepareTestContainerSelfManaged(t *testing.T) (func(), *url.URL) {
	return prepareTestContainerSelfManaged(t, defaultRunOpts(t), defaultPGPass, true, false, false)
}

func prepareTestContainerSelfManaged(t *testing.T, runOpts docker.RunOptions, password string, addSuffix, forceLocalAddr, useFallback bool,
) (func(), *url.URL) {
	if os.Getenv("PG_URL") != "" {
		return func() {}, nil
	}

	runner, err := docker.NewServiceRunner(runOpts)
	if err != nil {
		t.Fatalf("Could not start docker Postgres: %s", err)
	}

	svc, _, err := runner.StartNewService(context.Background(), addSuffix, forceLocalAddr, connectPostgres(password, runOpts.ImageRepo, useFallback))
	if err != nil {
		t.Fatalf("Could not start docker Postgres: %s", err)
	}

	return svc.Cleanup, svc.Config.URL()
}

func connectPostgres(password, repo string, useFallback bool) docker.ServiceAdapter {
	return func(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
		hostAddr := fmt.Sprintf("%s:%d", host, port)
		if useFallback {
			// set the first host to a bad address so we can test the fallback logic
			hostAddr = "localhost:55," + hostAddr
		}
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword("postgres", password),
			Host:     hostAddr,
			Path:     "postgres",
			RawQuery: "sslmode=disable",
		}

		db, err := sql.Open("pgx", u.String())
		if err != nil {
			return nil, err
		}
		defer db.Close()

		_, err = db.ExecContext(context.Background(), `SELECT set_config('log_statement', 'all', false);`)
		if err != nil {
			return nil, err
		}

		if err = db.Ping(); err != nil {
			return nil, err
		}
		return docker.NewServiceURL(u), nil
	}
}
