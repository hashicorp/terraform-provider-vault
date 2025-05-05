// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAWSAuthBackendRole_importInferred(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_aws_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_inferred(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"bound_ami_id", "bound_account_id", "bound_region",
					"bound_vpc_id", "bound_subnet_id", "bound_iam_role_arn",
					"bound_iam_instance_profile_arn", "bound_ec2_instance_id",
					"bound_iam_principal_arn",
				},
			},
		},
	})
}

func TestAccAWSAuthBackendRole_importEC2(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_aws_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_ec2(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAuthBackendRole_importIAM(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_aws_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_iam(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAuthBackendRole_inferred(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_aws_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_inferred(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
			},
		},
	})
}

func TestAccAWSAuthBackendRole_ec2(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_aws_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_ec2(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
			},
		},
	})
}

func TestAccAWSAuthBackendRole_iam(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_aws_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_iam(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
			},
		},
	})
}

func TestAccAWSAuthBackendRole_iam_resolve_aws_unique_ids(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_aws_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_iam_resolve_aws_unique_ids(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
			},
		},
	})
}

func TestAccAWSAuthBackendRole_iamUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_aws_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_iam(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
			},
			{
				Config: testAccAWSAuthBackendRoleConfig_iamUpdate(backend, role),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
					resource.TestCheckResourceAttr(resourceName, "bound_iam_principal_arns.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "bound_iam_principal_arns.0", "arn:aws:iam::123456789012:role/MyRole/*"),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "30"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "60"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.0", "default"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.1", "dev"),
				),
			},
			{
				Config: testAccAWSAuthBackendRoleConfig_DeletePolicies(backend, role),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "0"),
				),
			},
			{
				Config: testAccAWSAuthBackendRoleConfig_Unset(backend, role),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "0"),
				),
			},
		},
	})
}

func testAccCheckAWSAuthBackendRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AWS auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AWS auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAWSAuthBackendRoleCheck_attrs(resourceName, backend, role string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		path := rs.Primary.ID

		expectedPath := "auth/" + backend + "/role/" + role
		if path != expectedPath {
			return fmt.Errorf("expected ID to be %q, got %q instead", expectedPath, path)
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"auth_type":                       "auth_type",
			"bound_ami_ids":                   "bound_ami_id",
			"bound_account_ids":               "bound_account_id",
			"bound_regions":                   "bound_region",
			"bound_vpc_ids":                   "bound_vpc_id",
			"bound_subnet_ids":                "bound_subnet_id",
			"bound_iam_role_arns":             "bound_iam_role_arn",
			"bound_iam_instance_profile_arns": "bound_iam_instance_profile_arn",
			"bound_ec2_instance_ids":          "bound_ec2_instance_id",
			"role_tag":                        "role_tag",
			"role_id":                         "role_id",
			"bound_iam_principal_arns":        "bound_iam_principal_arn",
			"inferred_entity_type":            "inferred_entity_type",
			"inferred_aws_region":             "inferred_aws_region",
			"resolve_aws_unique_ids":          "resolve_aws_unique_ids",
			"token_ttl":                       "token_ttl",
			"token_max_ttl":                   "token_max_ttl",
			"token_period":                    "token_period",
			"token_policies":                  "token_policies",
			"allow_instance_migration":        "allow_instance_migration",
			"disallow_reauthentication":       "disallow_reauthentication",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}
			switch k {
			case "token_policies":
				ta.AsSet = true
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAccAWSAuthBackendRoleConfig_inferred(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_ami_ids = ["ami-8c1be5f6"]
  bound_account_ids = ["123456789012"]
  bound_vpc_ids = ["vpc-b61106d4"]
  bound_subnet_ids = ["vpc-a33128f1"]
  bound_iam_role_arns = ["arn:aws:iam::123456789012:role/S3Access"]
  bound_iam_instance_profile_arns = ["arn:aws:iam::123456789012:instance-profile/Webserver"]
  bound_ec2_instance_ids = ["i-06bb291939760ba66"]
  inferred_entity_type = "ec2_instance"
  inferred_aws_region = "us-east-1"
  token_ttl = 60
  token_max_ttl = 120
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_iam(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/*"]
  resolve_aws_unique_ids = true
  token_ttl = 60
  token_max_ttl = 120
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_iam_resolve_aws_unique_ids(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/*"]
  resolve_aws_unique_ids = false
  token_ttl = 60
  token_max_ttl = 120
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_iamUpdate(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/MyRole/*"]
  resolve_aws_unique_ids = true
  token_ttl = 30
  token_max_ttl = 60
  token_policies = ["default", "dev"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_DeletePolicies(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/MyRole/*"]
  resolve_aws_unique_ids = true
  token_ttl = 30
  token_max_ttl = 60
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_Unset(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/MyRole/*"]
  resolve_aws_unique_ids = true
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_ec2(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "ec2"
  bound_ami_ids = ["ami-8c1be5f6"]
  bound_account_ids = ["123456789012"]
  bound_regions = ["us-east-1"]
  bound_vpc_ids = ["vpc-b61106d4"]
  bound_subnet_ids = ["vpc-a33128f1"]
  bound_iam_role_arns = ["arn:aws:iam::123456789012:role/S3Access"]
  bound_iam_instance_profile_arns = ["arn:aws:iam::123456789012:instance-profile/Webserver"]
  bound_ec2_instance_ids = ["i-06bb291939760ba66"]
  role_tag = "VaultRoleTag"
  disallow_reauthentication = true
  token_ttl = 60
  token_max_ttl = 120
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
}

type fieldNames struct {
	NameInVault            string
	NameInProvider         string
	PreviousNameInProvider string
}
