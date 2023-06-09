package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceAWSStaticCredentials(t *testing.T) {
	_, _ = testutil.GetTestAWSCreds(t)
	username := testutil.SkipTestEnvUnset(t, "AWS_STATIC_USER")[0]
	mount := acctest.RandomWithPrefix("tf-aws-static")
	resourceName := "data.vault_aws_static_access_credentials.creds"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAWSStaticDataSourceConfig(mount, username),
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

func testAWSStaticDataSourceConfig(mount, username string) string {
	return fmt.Sprintf(testAWSStaticDataResource, mount, username)
}
