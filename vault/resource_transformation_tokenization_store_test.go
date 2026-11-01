package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	testTokenizationStorePostgresConnURL = "postgresql://vaultuser:vaultpass@127.0.0.1:5432/vault?sslmode=disable"
	testTokenizationStoreMysqlConnURL    = "vaultuser:vaultpass@tcp(127.0.0.1:3306)/vault"
)

func TestAccTransformTokenizationStore_postgres(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resourceName := "vault_transform_transformation_tokenization_store.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTokenizationStoreDestroy,
		Steps: []resource.TestStep{
			{
				Config: transformTokenizationStorePostgresConfig(path, "test-store"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "test-store"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "sql"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDriver, "postgres"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionString, testTokenizationStorePostgresConnURL),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportedTransformations+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportedTransformations+".0", "tokenization"),
				),
			},
			// Update mutable fields
			{
				Config: transformTokenizationStorePostgresConfigWithOptions(path, "test-store", 10, 5),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxOpenConnections, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxIdleConnections, "5"),
				),
			},
			// Idempotency check
			{
				Config: transformTokenizationStorePostgresConfigWithOptions(path, "test-store", 10, 5),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldType, consts.FieldUsername, consts.FieldPassword, consts.FieldSchema, consts.FieldMaxOpenConnections, consts.FieldMaxIdleConnections, consts.FieldMaxConnectionLifetime},
			},
		},
	})
}

func TestAccTransformTokenizationStore_mysql(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resourceName := "vault_transform_transformation_tokenization_store.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTokenizationStoreDestroy,
		Steps: []resource.TestStep{
			{
				Config: transformTokenizationStoreMysqlConfig(path, "test-store"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "test-store"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "sql"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDriver, "mysql"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConnectionString, testTokenizationStoreMysqlConnURL),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportedTransformations+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportedTransformations+".0", "tokenization"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldType, consts.FieldUsername, consts.FieldPassword, consts.FieldSchema, consts.FieldMaxOpenConnections, consts.FieldMaxIdleConnections, consts.FieldMaxConnectionLifetime},
			},
		},
	})
}

func transformTokenizationStoreDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_transformation_tokenization_store" {
			continue
		}
		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for store %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("store %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func transformTokenizationStorePostgresConfig(path, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation_tokenization_store" "test" {
  path                      = vault_mount.mount_transform.path
  name                      = "%s"
  type                      = "sql"
  driver                    = "postgres"
  connection_string         = "%s"
  username                  = "vaultuser"
  password                  = "vaultpass"
  supported_transformations = ["tokenization"]
}`, path, name, testTokenizationStorePostgresConnURL)
}

func transformTokenizationStorePostgresConfigWithOptions(path, name string, maxOpen, maxIdle int) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation_tokenization_store" "test" {
  path                      = vault_mount.mount_transform.path
  name                      = "%s"
  type                      = "sql"
  driver                    = "postgres"
  connection_string         = "%s"
  username                  = "vaultuser"
  password                  = "vaultpass"
  supported_transformations = ["tokenization"]
  max_open_connections      = %d
  max_idle_connections      = %d
}`, path, name, testTokenizationStorePostgresConnURL, maxOpen, maxIdle)
}

func transformTokenizationStoreMysqlConfig(path, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation_tokenization_store" "test" {
  path                      = vault_mount.mount_transform.path
  name                      = "%s"
  type                      = "sql"
  driver                    = "mysql"
  connection_string         = "%s"
  username                  = "vaultuser"
  password                  = "vaultpass"
  supported_transformations = ["tokenization"]
}`, path, name, testTokenizationStoreMysqlConnURL)
}
