// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAWSAuthBackendRoleTag_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	role := acctest.RandomWithPrefix("tf-test-aws")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleTagConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_role_tag.test", "tag_value"),
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_role_tag.test", "tag_key"),
				),
			},
		},
	})
}

func testAccAWSAuthBackendRoleTagConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
    path = "%s"
    type = "aws"
}

resource "vault_aws_auth_backend_role" "role" {
    backend = vault_auth_backend.aws.path
    role = "%s"
    auth_type = "ec2"
    bound_account_ids = ["123456789012"]
    token_policies = ["dev", "prod", "qa", "test"]
    role_tag = "VaultRoleTag"
}

resource "vault_aws_auth_backend_role_tag" "test" {
    backend = vault_auth_backend.aws.path
    role = vault_aws_auth_backend_role.role.role
    policies = ["prod", "dev", "test"]
    max_ttl = "1h"
    instance_id = "i-1234567"
}`, backend, role)
}
