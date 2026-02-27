// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceAWSStaticCredentials(t *testing.T) {
	a, s := testutil.GetTestAWSCreds(t)
	username := testutil.SkipTestEnvUnset(t, "AWS_STATIC_USER")[0]
	mount := acctest.RandomWithPrefix("tf-aws-static")
	resourceName := "data.vault_aws_static_access_credentials.creds"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)

		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testAWSStaticDataSourceConfig(mount, a, s, username),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessKey),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldSecretKey),
				),
			},
		},
	})
}

const testAWSStaticDataResource = `
resource "vault_aws_secret_backend" "aws" {
  path = "%s"
  description = "Obtain AWS credentials."
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_backend_static_role" "role" {
  backend = vault_aws_secret_backend.aws.path
  name = "test"
  username = "%s"
  rotation_period = "3600"
}

data "vault_aws_static_access_credentials" "creds" {
  backend = vault_aws_secret_backend.aws.path
  name = vault_aws_secret_backend_static_role.role.name
}`

func testAWSStaticDataSourceConfig(mount, access, secret, username string) string {
	return fmt.Sprintf(testAWSStaticDataResource, mount, access, secret, username)
}
