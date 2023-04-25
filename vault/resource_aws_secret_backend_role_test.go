// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	testAccAWSSecretBackendRolePolicyInline_basic             = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "iam:*","Resource": "*"}]}`
	testAccAWSSecretBackendRolePolicyInline_updated           = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "ec2:*","Resource": "*"}]}`
	testAccAWSSecretBackendRolePolicyArn_basic                = "arn:aws:iam::123456789123:policy/foo"
	testAccAWSSecretBackendRolePolicyArn_updated              = "arn:aws:iam::123456789123:policy/bar"
	testAccAWSSecretBackendRoleRoleArn_basic                  = "arn:aws:iam::123456789123:role/foo"
	testAccAWSSecretBackendRoleRoleArn_updated                = "arn:aws:iam::123456789123:role/bar"
	testAccAWSSecretBackendRolePermissionsBoundaryArn_basic   = "arn:aws:iam::123456789123:policy/boundary1"
	testAccAWSSecretBackendRolePermissionsBoundaryArn_updated = "arn:aws:iam::123456789123:policy/boundary2"
	testAccAWSSecretBackendRoleIamUserPath_basic              = "/path1/"
	testAccAWSSecretBackendRoleIamUserPath_updated            = "/path2/"
)

func TestAccAWSSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check:  testAccAWSSecretBackendRoleCheckBasicAttributes(name, backend),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check:  testAccAWSSecretBackendRoleCheckUpdatedAttributes(name, backend),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check:  testAccAWSSecretBackendRoleCheckBasicAttributes(name, backend),
			},
		},
	})
}

func TestAccAWSSecretBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check:  testAccAWSSecretBackendRoleCheckBasicAttributes(name, backend),
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
			{
				ResourceName:      "vault_aws_secret_backend_role.test_iam_user_type_optional_attributes",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSSecretBackendRole_nested(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws/nested")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check:  testAccAWSSecretBackendRoleCheckBasicAttributes(name, backend),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check:  testAccAWSSecretBackendRoleCheckUpdatedAttributes(name, backend),
			},
		},
	})
}

func testAccAWSSecretBackendRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_secret_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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

func testAccAWSSecretBackendRoleCheckBasicAttributes(name, backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
		testutil.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "iam_groups.#", "0"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
		testutil.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "name", fmt.Sprintf("%s-role-arns", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "backend", backend),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.0", testAccAWSSecretBackendRoleRoleArn_basic),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_to_arn", "name", fmt.Sprintf("%s-policy-inline-to-arn", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_to_arn", "backend", backend),
		testutil.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_to_arn", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "name", fmt.Sprintf("%s-iam-user-type-optional-attributes", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "backend", backend),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "policy_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "permissions_boundary_arn", testAccAWSSecretBackendRolePermissionsBoundaryArn_basic),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "user_path", testAccAWSSecretBackendRoleIamUserPath_basic),
	)
}

func testAccAWSSecretBackendRoleCheckUpdatedAttributes(name, backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "default_sts_ttl", "3600"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "max_sts_ttl", "21600"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "iam_groups.#", "2"),
		testutil.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "iam_groups.#", "2"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
		testutil.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "iam_groups.#", "2"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "name", fmt.Sprintf("%s-role-arns", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "backend", backend),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "role_arns.0", testAccAWSSecretBackendRoleRoleArn_updated),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_role_arns", "iam_groups.#", "2"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_to_arn", "name", fmt.Sprintf("%s-policy-inline-to-arn", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_to_arn", "backend", backend),
		testutil.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_to_arn", "policy_document", ""),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_to_arn", "policy_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_to_arn", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "name", fmt.Sprintf("%s-iam-user-type-optional-attributes", name)),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "backend", backend),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "policy_arns.#", "1"),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "permissions_boundary_arn", testAccAWSSecretBackendRolePermissionsBoundaryArn_updated),
		resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_iam_user_type_optional_attributes", "user_path", testAccAWSSecretBackendRoleIamUserPath_updated),
	)
}

func testAccAWSSecretBackendRoleConfig_basic(name, path, accessKey, secretKey string) string {
	resources := []string{
		fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}
`, path, accessKey, secretKey),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_policy_inline" {
  name = "%s-policy-inline"
  policy_document = %q
  credential_type = "assumed_role"
  backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRolePolicyInline_basic),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arn"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRolePolicyArn_basic),

		fmt.Sprintf(`

resource "vault_aws_secret_backend_role" "test_policy_inline_and_arns" {
  name = "%s-policy-inline-and-arns"
  policy_document = %q
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRolePolicyInline_basic, testAccAWSSecretBackendRolePolicyArn_basic),

		fmt.Sprintf(`

resource "vault_aws_secret_backend_role" "test_role_arns" {
  name = "%s-role-arns"
  role_arns = ["%s"]
  credential_type = "assumed_role"
  backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRoleRoleArn_basic),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_policy_inline_to_arn" {
  name = "%s-policy-inline-to-arn"
  policy_document = %q
  credential_type = "assumed_role"
  backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRolePolicyInline_basic),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_iam_user_type_optional_attributes" {
  name = "%s-iam-user-type-optional-attributes"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = vault_aws_secret_backend.test.path
  permissions_boundary_arn = "%s"
  user_path = "%s"
}
`, name, testAccAWSSecretBackendRolePolicyArn_basic, testAccAWSSecretBackendRolePermissionsBoundaryArn_basic, testAccAWSSecretBackendRoleIamUserPath_basic),
	}

	return strings.Join(resources, "\n")
}

func testAccAWSSecretBackendRoleConfig_updated(name, path, accessKey, secretKey string) string {
	resources := []string{
		fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}
`, path, accessKey, secretKey),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_policy_inline" {
  name = "%s-policy-inline"
  policy_document = %q
  credential_type = "assumed_role"
  backend = vault_aws_secret_backend.test.path
  default_sts_ttl = 3600
  max_sts_ttl = 21600
  iam_groups = ["group1", "group2"]
}
`, name, testAccAWSSecretBackendRolePolicyInline_updated),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arn"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  iam_groups = ["group1", "group2"]
  backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRolePolicyArn_updated),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_policy_inline_and_arns" {
  name = "%s-policy-inline-and-arns"
  policy_document = %q
  policy_arns = ["%s"]
  credential_type = "iam_user"
  iam_groups = ["group1", "group2"]
  backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRolePolicyInline_updated, testAccAWSSecretBackendRolePolicyArn_updated),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_role_arns" {
    name = "%s-role-arns"
    role_arns = ["%s"]
    credential_type = "assumed_role"
    iam_groups = ["group1", "group2"]
    backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRoleRoleArn_updated),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_role_groups" {
    name = "%s-role-groups"
    credential_type = "assumed_role"
    iam_groups = ["group1", "group2"]
    backend = vault_aws_secret_backend.test.path
}
`, name),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_policy_inline_to_arn" {
  name = "%s-policy-inline-to-arn"
  policy_arns = ["%s"]
  credential_type = "assumed_role"
  backend = vault_aws_secret_backend.test.path
}
`, name, testAccAWSSecretBackendRolePolicyArn_updated),

		fmt.Sprintf(`
resource "vault_aws_secret_backend_role" "test_iam_user_type_optional_attributes" {
  name = "%s-iam-user-type-optional-attributes"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = vault_aws_secret_backend.test.path
  permissions_boundary_arn = "%s"
  user_path = "%s"
}
`, name, testAccAWSSecretBackendRolePolicyArn_updated, testAccAWSSecretBackendRolePermissionsBoundaryArn_updated, testAccAWSSecretBackendRoleIamUserPath_updated),
	}
	return strings.Join(resources, "\n")
}
