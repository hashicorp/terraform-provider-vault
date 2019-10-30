package testing

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/hashicorp/go-hclog"
	"github.com/ory/dockertest"
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
	return cleanup, retURL
}