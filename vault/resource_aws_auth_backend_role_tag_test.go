package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
)

func TestAccAWSAuthBackendRoleTag_basic_current(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	role := acctest.RandomWithPrefix("tf-test-aws")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleTagConfig_basic_current(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_role_tag.test", "tag_value"),
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_role_tag.test", "tag_key"),
				),
			},
		},
	})
}

func TestAccAWSAuthBackendRoleTag_basic_deprecated(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	role := acctest.RandomWithPrefix("tf-test-aws")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleTagConfig_basic_deprecated(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_role_tag.test", "tag_value"),
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_role_tag.test", "tag_key"),
				),
			},
		},
	})
}

func testAccAWSAuthBackendRoleTagConfig_basic_current(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
    path = "%s"
    type = "aws"
}

resource "vault_aws_auth_backend_role" "role" {
    backend = "${vault_auth_backend.aws.path}"
    role = "%s"
    auth_type = "ec2"
    bound_account_ids = ["123456789012"]
    policies = ["dev", "prod", "qa", "test"]
    role_tag = "VaultRoleTag"
}

resource "vault_aws_auth_backend_role_tag" "test" {
    backend = "${vault_auth_backend.aws.path}"
    role = "${vault_aws_auth_backend_role.role.role}"
    policies = ["prod", "dev", "test"]
    max_ttl = "1h"
    instance_id = "i-1234567"
}`, backend, role)
}

func testAccAWSAuthBackendRoleTagConfig_basic_deprecated(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
    path = "%s"
    type = "aws"
}

resource "vault_aws_auth_backend_role" "role" {
    backend = "${vault_auth_backend.aws.path}"
    role = "%s"
    auth_type = "ec2"
    bound_account_id = "123456789012"
    policies = ["dev", "prod", "qa", "test"]
    role_tag = "VaultRoleTag"
}

resource "vault_aws_auth_backend_role_tag" "test" {
    backend = "${vault_auth_backend.aws.path}"
    role = "${vault_aws_auth_backend_role.role.role}"
    policies = ["prod", "dev", "test"]
    max_ttl = "1h"
    instance_id = "i-1234567"
}`, backend, role)
}
