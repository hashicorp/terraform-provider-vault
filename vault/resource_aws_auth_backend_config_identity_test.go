// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAwsAuthBackendConfigIdentity(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_config_identity.config"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAwsAuthBackendConfigIdentityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAwsAuthBackendConfigIdentity_basic(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMAlias, "unique_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".0", "client_arn"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".1", "inferred_aws_region"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEC2Alias, "role_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEC2Metadata+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEC2Metadata+".0", "account_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEC2Metadata+".1", "auth_type"),
				),
			},
			{
				Config: testAccAwsAuthBackendConfigIdentity_updated(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMAlias, "full_arn"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".0", "client_user_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEC2Alias, "role_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEC2Metadata+".#", "0"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testAccCheckAwsAuthBackendConfigIdentityDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_config_identity" {
			continue
		}
		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AWS auth backend %q config: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AWS auth backend %q still configured", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAwsAuthBackendConfigIdentity_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for AWS backend config"
}

resource "vault_aws_auth_backend_config_identity" "config" {
  backend = vault_auth_backend.aws.path
  iam_alias = "unique_id"
  iam_metadata = ["inferred_aws_region", "client_arn"]
  ec2_metadata = ["account_id", "auth_type"]
}
`, backend)
}

func testAccAwsAuthBackendConfigIdentity_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend config"
}

resource "vault_aws_auth_backend_config_identity" "config" {
  backend = vault_auth_backend.aws.path
  iam_alias = "full_arn"
  iam_metadata = ["client_user_id"]
}`, backend)
}
