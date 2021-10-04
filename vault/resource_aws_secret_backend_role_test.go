package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/util"
)

const testAccAWSSecretBackendRolePolicyInline_basic = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "iam:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyInline_updated = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "ec2:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyArn_basic = "arn:aws:iam::123456789123:policy/foo"
const testAccAWSSecretBackendRolePolicyArn_updated = "arn:aws:iam::123456789123:policy/bar"
const testAccAWSSecretBackendRoleRoleArn_basic = "arn:aws:iam::123456789123:role/foo"
const testAccAWSSecretBackendRoleRoleArn_updated = "arn:aws:iam::123456789123:role/bar"

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
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "iam_groups.#", "0"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "name", fmt.Sprintf("%s-role-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.0", testAccAWSSecretBackendRoleRoleArn_basic),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "default_sts_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "max_sts_ttl", "21600"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "iam_groups.#", "2"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "iam_groups.#", "2"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "iam_groups.#", "2"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "name", fmt.Sprintf("%s-role-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.0", testAccAWSSecretBackendRoleRoleArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "iam_groups.#", "2"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_groups", "name", fmt.Sprintf("%s-role-groups", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_groups", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_groups", "iam_groups.#", "2"),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "iam_groups.#", "0"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "name", fmt.Sprintf("%s-role-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.0", testAccAWSSecretBackendRoleRoleArn_basic),
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
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "name", fmt.Sprintf("%s-role-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.0", testAccAWSSecretBackendRoleRoleArn_basic),
				),
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_inline",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_arns",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_inline_and_arns",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_role_arns",
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
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "name", fmt.Sprintf("%s-role-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.0", testAccAWSSecretBackendRoleRoleArn_basic),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "default_sts_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "max_sts_ttl", "21600"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "iam_groups.#", "2"),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "iam_groups.#", "2"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "iam_groups.#", "2"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "name", fmt.Sprintf("%s-role-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.0", testAccAWSSecretBackendRoleRoleArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "iam_groups.#", "2"),
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
  policy_document = %q
  credential_type = "assumed_role"
  backend = vault_aws_secret_backend.test.path
}

resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arn"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = vault_aws_secret_backend.test.path
}

resource "vault_aws_secret_backend_role" "test_policy_inline_and_arns" {
  name = "%s-policy-inline-and-arns"
  policy_document = %q
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = vault_aws_secret_backend.test.path
}

resource "vault_aws_secret_backend_role" "test_role_arns" {
	name = "%s-role-arns"
	role_arns = ["%s"]
	credential_type = "assumed_role"
	backend = vault_aws_secret_backend.test.path
}
`, path, accessKey, secretKey, name, testAccAWSSecretBackendRolePolicyInline_basic, name, testAccAWSSecretBackendRolePolicyArn_basic, name, testAccAWSSecretBackendRolePolicyInline_basic, testAccAWSSecretBackendRolePolicyArn_basic, name, testAccAWSSecretBackendRoleRoleArn_basic)
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
  policy_document = %q
  credential_type = "assumed_role"
  backend = vault_aws_secret_backend.test.path
  default_sts_ttl = 3600
  max_sts_ttl = 21600
  iam_groups = ["group1", "group2"]
}

resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arn"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  iam_groups = ["group1", "group2"]
  backend = vault_aws_secret_backend.test.path
}

resource "vault_aws_secret_backend_role" "test_policy_inline_and_arns" {
  name = "%s-policy-inline-and-arns"
  policy_document = %q
  policy_arns = ["%s"]
  credential_type = "iam_user"
  iam_groups = ["group1", "group2"]
  backend = vault_aws_secret_backend.test.path
}

resource "vault_aws_secret_backend_role" "test_role_arns" {
	name = "%s-role-arns"
	role_arns = ["%s"]
	credential_type = "assumed_role"
	iam_groups = ["group1", "group2"]
	backend = vault_aws_secret_backend.test.path
}

resource "vault_aws_secret_backend_role" "test_role_groups" {
	name = "%s-role-groups"
	credential_type = "assumed_role"
	iam_groups = ["group1", "group2"]
	backend = vault_aws_secret_backend.test.path
}
`, path, accessKey, secretKey, name, testAccAWSSecretBackendRolePolicyInline_updated, name, testAccAWSSecretBackendRolePolicyArn_updated, name, testAccAWSSecretBackendRolePolicyInline_updated, testAccAWSSecretBackendRolePolicyArn_updated, name, testAccAWSSecretBackendRoleRoleArn_updated, name)
}
