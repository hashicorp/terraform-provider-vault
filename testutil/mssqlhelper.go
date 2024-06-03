// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/docker"
)

const (
	mssqlNumRetries = 3
	mssqlPassword   = "yourStrong(!)Password"
)

// PrepareMSSQLTestContainer sets up a test MSSQL docker container
func PrepareMSSQLTestContainer(t *testing.T) (cleanup func(), retURL string) {
	if strings.Contains(runtime.GOARCH, "arm") {
		t.Skip("Skipping, as this image is not supported on ARM architectures")
	}

	if os.Getenv("MSSQL_URL") != "" {
		return func() {}, os.Getenv("MSSQL_URL")
	}

	var err error
	for i := 0; i < mssqlNumRetries; i++ {
		var svc *docker.Service
		runner, err := docker.NewServiceRunner(docker.RunOptions{
			ContainerName: "sqlserver",
			ImageRepo:     "mcr.microsoft.com/mssql/server",
			ImageTag:      "2017-latest-ubuntu",
			Env:           []string{"ACCEPT_EULA=Y", "SA_PASSWORD=" + mssqlPassword},
			Ports:         []string{"1433/tcp"},
			LogConsumer: func(s string) {
				if t.Failed() {
					t.Logf("container logs: %s", s)
				}
			},
		})
		if err != nil {
			t.Fatalf("Could not start docker MSSQL: %s", err)
		}

		svc, err = runner.StartService(context.Background(), connectMSSQL)
		if err == nil {
			return svc.Cleanup, svc.Config.URL().String()
		}
	}

	t.Fatalf("Could not start docker MSSQL: %s", err)
	return nil, ""
}

func connectMSSQL(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
	u := url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword("sa", mssqlPassword),
		Host:   fmt.Sprintf("%s:%d", host, port),
	}
	// Attempt to address connection flakiness within tests such as "Failed to initialize: error verifying connection ..."
	u.Query().Add("Connection Timeout", "30")

	db, err := sql.Open("mssql", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return docker.NewServiceURL(u), nil
}
