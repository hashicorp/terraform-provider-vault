package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

const testAccAWSSecretBackendRolePolicyInline_basic = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "iam:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyInline_updated = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "ec2:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyArn_basic = "arn:aws:iam::123456789123:policy/foo"
const testAccAWSSecretBackendRolePolicyArn_updated = "arn:aws:iam::123456789123:policy/bar"

func TestAccAWSSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_basic),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_updated),
				),
			},
		},
	})
}

func TestAccAWSSecretBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_basic),
				),
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_inline",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_arn",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSSecretBackendRole_nested(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws/nested")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_basic),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_updated),
				),
			},
		},
	})
}

func testAccAWSSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_secret_backend_role" {
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

func testAccAWSSecretBackendRoleConfig_basic(name, path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_backend_role" "test_policy_inline" {
  name = "%s-policy-inline"
  policy = %q
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arn" {
  name = "%s-policy-arn"
  policy_arn = "%s"
  backend = "${vault_aws_secret_backend.test.path}"
}
`, path, accessKey, secretKey, name, testAccAWSSecretBackendRolePolicyInline_basic, name, testAccAWSSecretBackendRolePolicyArn_basic)
}

func testAccAWSSecretBackendRoleConfig_updated(name, path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_backend_role" "test_policy_inline" {
  name = "%s-policy-inline"
  policy = %q
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arn" {
  name = "%s-policy-arn"
  policy_arn = "%s"
  backend = "${vault_aws_secret_backend.test.path}"
}
`, path, accessKey, secretKey, name, testAccAWSSecretBackendRolePolicyInline_updated, name, testAccAWSSecretBackendRolePolicyArn_updated)
}
