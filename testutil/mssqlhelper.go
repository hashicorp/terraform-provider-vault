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
	// skip due to error:
	// tls: failed to parse certificate from server: x509: negative serial number in test case failures.
	t.Skip("Skipping until https://github.com/microsoft/mssql-docker/issues/895 is resolved.")

	if strings.Contains(runtime.GOARCH, "arm") {
		t.Skip("Skipping, as this image is not supported on ARM architectures")
	}

	if os.Getenv("MSSQL_URL") != "" {
		return func() {}, os.Getenv("MSSQL_URL")
	}

	containerfile := `
FROM mcr.microsoft.com/mssql/server:2017-latest
USER root
ENV MSDIR=/var/opt/mssql
RUN mkdir -p $MSDIR \
    && openssl req -x509 -nodes -newkey rsa:2048 -subj '/CN=mssql' -addext "subjectAltName = DNS:mssql" -keyout $MSDIR/mssql.key -out $MSDIR/mssql.pem -days 1 \
	&& chmod 400 $MSDIR/mssql.key \
	&& chmod 400 $MSDIR/mssql.pem \
    && chown -R mssql $MSDIR
RUN echo "[network]" > $MSDIR/mssql.conf \
	&& echo "tlscert = $MSDIR/mssql.pem" >> $MSDIR/mssql.conf \
	&& echo "tlskey = $MSDIR/mssql.key" >> $MSDIR/mssql.conf \ 
	&& echo "tlsprotocols = 1.2" >> $MSDIR/mssql.conf \ 
	&& echo "forceencryption = 1" >> $MSDIR/mssql.conf 
USER mssql
`
	bCtx := docker.NewBuildContext()
	imageName := "mssql-workaround-895"
	imageTag := "latest"

	runner, err := docker.NewServiceRunner(docker.RunOptions{
		ContainerName: "sqlserver",
		ImageRepo:     imageName,
		ImageTag:      imageTag,
		Env:           []string{"ACCEPT_EULA=Y", "SA_PASSWORD=" + mssqlPassword},
		Ports:         []string{"1433/tcp"},
	})
	if err != nil {
		t.Fatalf("Could not provision docker service runner: %s", err)
	}

	for i := 0; i < 3; i++ {
		_, err = runner.BuildImage(context.Background(), containerfile, bCtx,
			docker.BuildRemove(true),
			docker.BuildForceRemove(true),
			docker.BuildPullParent(true),
			docker.BuildTags([]string{imageName + ":" + imageTag}))
		if err == nil {
			var svc *docker.Service
			svc, err = runner.StartService(context.Background(), connectMSSQL)
			if err == nil {
				return svc.Cleanup, svc.Config.URL().String()
			}
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
