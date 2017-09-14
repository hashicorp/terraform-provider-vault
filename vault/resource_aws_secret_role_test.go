package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

const testAccAWSSecretRolePolicy_basic = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "iam:*","Resource": "*"}]}`

const testAccAWSSecretRolePolicy_updated = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "ec2:*","Resource": "*"}]}`

func TestAccAWSSecretRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_aws_secret_role.test", "backend", backend),
					testCheckResourceAttrJSON("vault_aws_secret_role.test", "policy", testAccAWSSecretRolePolicy_basic),
				),
			},
			{
				Config: testAccAWSSecretRoleConfig_updated(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_aws_secret_role.test", "backend", backend),
					testCheckResourceAttrJSON("vault_aws_secret_role.test", "policy", testAccAWSSecretRolePolicy_updated),
				),
			},
		},
	})
}

func TestAccAWSSecretRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_aws_secret_role.test", "backend", backend),
					testCheckResourceAttrJSON("vault_aws_secret_role.test", "policy", testAccAWSSecretRolePolicy_basic),
				),
			},
			{
				ResourceName:      "vault_aws_secret_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccAWSSecretRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_secret_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAWSSecretRoleConfig_basic(name, path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_role" "test" {
  name = "%s"
  policy = %q
  backend = "${vault_aws_secret_backend.test.path}"
}
`, path, accessKey, secretKey, name, testAccAWSSecretRolePolicy_basic)
}

func testAccAWSSecretRoleConfig_updated(name, path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_role" "test" {
  name = "%s"
  policy = %q
  backend = "${vault_aws_secret_backend.test.path}"
}
`, path, accessKey, secretKey, name, testAccAWSSecretRolePolicy_updated)
}
