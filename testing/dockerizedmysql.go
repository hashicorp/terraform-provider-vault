package testing

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/hashicorp/go-hclog"
	"github.com/ory/dockertest"
	"os"
	"testing"
)

func PrepareMySQLTestContainer(t *testing.T) (func(), string) {
	if os.Getenv("MYSQL_URL") != "" {
		return func() {}, os.Getenv("MYSQL_URL")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	resource, err := pool.Run("mysql", "5.7", []string{"MYSQL_ROOT_PASSWORD=secret"})
	if err != nil {
		t.Fatalf("Could not start local MySQL docker container: %s", err)
	}

	cleanup := func() {
		cleanupResource(t, pool, resource)
	}

	retURL := fmt.Sprintf("root:secret@(localhost:%s)/mysql?parseTime=true", resource.GetPort("3306/tcp"))

	// exponential backoff-retry
	if err = pool.Retry(func() error {
		var err error
		var db *sql.DB
		db, err = sql.Open("mysql", retURL)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Ping()
	}); err != nil {
		cleanup()
		t.Fatalf("Could not connect to MySQL docker container: %s", err)
	}
	hclog.Default().Info("successfully connected to " + retURL)
	/*
	2019-10-30T18:24:32.994Z [INFO]  successfully connected to root:secret@(localhost:32769)/mysql?parseTime=true
	--- FAIL: TestAccDatabaseSecretBackendRole_import (21.30s)
	    testing.go:569: Step 0 error: errors during apply:

	        Error: error configuring database connection "tf-test-db-302165647884812244/config/db-4435628045551665907": Error making API request.

	        URL: PUT http://localhost:8200/v1/tf-test-db-302165647884812244/config/db-4435628045551665907
	        Code: 400. Errors:

	        * error creating database object: error verifying connection: dial tcp 127.0.0.1:32769: connect: connection refused

	          on /tmp/tf-test431585029/main.tf line 7:
	          (source code not available)
	 */
	return cleanup, retURL
}