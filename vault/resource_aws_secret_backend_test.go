package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccAWSSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "access_key", accessKey),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "secret_key", secretKey),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "region", "us-east-1"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "iam_endpoint", ""),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "sts_endpoint", ""),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_updated(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "access_key", accessKey),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "secret_key", secretKey),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "region", "us-west-1"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "iam_endpoint", "https://iam.amazonaws.com"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "sts_endpoint", "https://sts.us-west-1.amazonaws.com"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_noCreds(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "access_key", ""),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "secret_key", ""),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "region", "us-west-1"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "iam_endpoint", ""),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "sts_endpoint", ""),
				),
			},
		},
	})
}

func TestAccAWSSecretBackend_import(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccAWSSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "access_key", accessKey),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "secret_key", secretKey),
					resource.TestCheckResourceAttr("vault_aws_secret_backend.test", "region", "us-east-1"),
				),
			},
			{
				ResourceName:      "vault_aws_secret_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"access_key", "secret_key", "region"},
			},
		},
	})
}

func testAccAWSSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "aws" && path == rsPath {
				return fmt.Errorf("mount %q still exists", path)
			}
		}
	}
	return nil
}

func testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  access_key = "%s"
  secret_key = "%s"
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_updated(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  access_key = "%s"
  secret_key = "%s"
  region = "us-west-1"

  iam_endpoint = "https://iam.amazonaws.com"
  sts_endpoint = "https://sts.us-west-1.amazonaws.com"
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_noCreds(path string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  region = "us-west-1"
}`, path)
}
