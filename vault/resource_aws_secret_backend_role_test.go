package vault

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

const testAccAWSSecretBackendRolePolicyInline_basic = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "iam:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyInline_updated = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "ec2:*","Resource": "*"}]}`

const testAccAWSSecretBackendRolePolicyDocument_basic = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "s3:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyDocument_updated = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "ecs:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyArn_basic = "arn:aws:iam::123456789123:policy/foo"
const testAccAWSSecretBackendRolePolicyArn_updated = "arn:aws:iam::123456789123:policy/bar"

func TestAccAWSSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")

	policies_basic := []string{"arn:aws:iam::123456789123:policy/fizz"}
	policies_updated := []string{"arn:aws:iam::123456789123:policy/buzz"}
	roles_basic := []string{"arn:aws:iam::123456789123:role/fizz"}
	roles_updated := []string{"arn:aws:iam::123456789123:role/buzz"}

	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey, policies_basic, roles_basic),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "name", fmt.Sprintf("%s-policy-document", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_document", "policy_document", testAccAWSSecretBackendRolePolicyDocument_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_basic),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_policy_arns", "policy_arns", policies_basic),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_role_arns", "role_arns", roles_basic),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey, policies_updated, roles_updated),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "name", fmt.Sprintf("%s-policy-document", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_document", "policy_document", testAccAWSSecretBackendRolePolicyDocument_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_updated),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_policy_arns", "policy_arns", policies_updated),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_role_arns", "role_arns", roles_updated),
				),
			},
		},
	})
}

func TestAccAWSSecretBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")

	policies_basic := []string{"arn:aws:iam::123456789123:policy/fizz"}
	roles_basic := []string{"arn:aws:iam::123456789123:role/fizz"}

	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_import(name, backend, accessKey, secretKey, policies_basic, roles_basic),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "name", fmt.Sprintf("%s-policy-document", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_document", "policy_document", testAccAWSSecretBackendRolePolicyDocument_basic),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_policy_arns", "policy_arns", policies_basic),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_role_arns", "role_arns", roles_basic),
				),
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_document",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_arns",
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

	policies_basic := []string{"arn:aws:iam::123456789123:policy/fizz"}
	policies_updated := []string{"arn:aws:iam::123456789123:policy/buzz"}
	roles_basic := []string{"arn:aws:iam::123456789123:role/fizz"}
	roles_updated := []string{"arn:aws:iam::123456789123:role/buzz"}

	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey, policies_basic, roles_basic),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "name", fmt.Sprintf("%s-policy-document", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_document", "policy_document", testAccAWSSecretBackendRolePolicyDocument_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_basic),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_policy_arns", "policy_arns", policies_basic),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_role_arns", "role_arns", roles_basic),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey, policies_updated, roles_updated),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "name", fmt.Sprintf("%s-policy-document", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_document", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_document", "policy_document", testAccAWSSecretBackendRolePolicyDocument_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arn", "policy_arn", testAccAWSSecretBackendRolePolicyArn_updated),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_policy_arns", "policy_arns", policies_updated),
					testAWSSecretBackendRoleCheck_values(backend, "vault_aws_secret_backend_role.test_role_arns", "role_arns", roles_updated),
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

func testAWSSecretBackendRoleCheck_values(backend, name, key string, value []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources[name]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(instanceState.ID)
		if err != nil {
			return err
		}

		values := util.ToStringArray(resp.Data[key].([]interface{}))

		count, err := strconv.Atoi(instanceState.Attributes[fmt.Sprintf("%s.#", key)])
		if err != nil {
			return err
		}
		if len(values) != count {
			return fmt.Errorf("saw %d %s on server, expected %d", len(values), key, count)
		}

		for _, value := range values {
			found := false
			for stateKey, stateValue := range instanceState.Attributes {
				if strings.HasPrefix(stateKey, fmt.Sprintf("%s.", key)) {
					if stateValue == value {
						found = true
						break
					}
				}
			}
			if !found {
				return fmt.Errorf("unable to find %s %s in state file", key, value)
			}
		}
		return nil
	}
}

func testAccAWSSecretBackendRoleConfig_basic(name, path, accessKey, secretKey string, policies_basic, roles_basic []string) string {
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

resource "vault_aws_secret_backend_role" "test_policy_document" {
  name = "%s-policy-document"
  policy_document = %q
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arn" {
  name = "%s-policy-arn"
  policy_arn = "%s"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arns"
  policy_arns = %s
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_role_arns" {
  name = "%s-role-arns"
  role_arns = %s
  backend = "${vault_aws_secret_backend.test.path}"
}
`, path, accessKey, secretKey, name, testAccAWSSecretBackendRolePolicyInline_basic, name, testAccAWSSecretBackendRolePolicyDocument_basic, name, testAccAWSSecretBackendRolePolicyArn_basic, name, util.ArrayToTerraformList(policies_basic), name, util.ArrayToTerraformList(roles_basic))
}

func testAccAWSSecretBackendRoleConfig_updated(name, path, accessKey, secretKey string, policies_updated, roles_updated []string) string {
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

resource "vault_aws_secret_backend_role" "test_policy_document" {
  name = "%s-policy-document"
  policy_document = %q
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arn" {
  name = "%s-policy-arn"
  policy_arn = "%s"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arns"
  policy_arns = %s
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_role_arns" {
  name = "%s-role-arns"
  role_arns = %s
  backend = "${vault_aws_secret_backend.test.path}"
}
`, path, accessKey, secretKey, name, testAccAWSSecretBackendRolePolicyInline_updated, name, testAccAWSSecretBackendRolePolicyDocument_updated, name, testAccAWSSecretBackendRolePolicyArn_updated, name, util.ArrayToTerraformList(policies_updated), name, util.ArrayToTerraformList(roles_updated))
}

func testAccAWSSecretBackendRoleConfig_import(name, path, accessKey, secretKey string, policies_basic, roles_basic []string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_backend_role" "test_policy_document" {
  name = "%s-policy-document"
  policy_document = %q
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arns"
  policy_arns = %s
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_role_arns" {
  name = "%s-role-arns"
  role_arns = %s
  backend = "${vault_aws_secret_backend.test.path}"
}
`, path, accessKey, secretKey, name, testAccAWSSecretBackendRolePolicyDocument_basic, name, util.ArrayToTerraformList(policies_basic), name, util.ArrayToTerraformList(roles_basic))
}
