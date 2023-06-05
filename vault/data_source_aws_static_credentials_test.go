package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"testing"
)

func TestAccDataSourceAWSStaticCredentials(t *testing.T) {
	//mountPath := acctest.RandomWithPrefix("tf-test-aws-static")
	//accessKey, secretKey := testutil.GetTestAWSCreds(t) // from the environment, causes test to skip if unset
	username := testutil.SkipTestEnvUnset(t, "AWS_STATIC_USER")[0]
	mount := acctest.RandomWithPrefix("tf-aws-static")

	resource.Test(t, resource.TestCase{
		IsUnitTest: false,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			//SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAWSStaticDataSourceConfig(mount, username),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_aws_static_access_credentials.creds", consts.FieldAccessKey),
					resource.TestCheckResourceAttrSet("data.vault_aws_static_access_credentials.creds", consts.FieldSecretKey),
				),
			},
		},
	})
}

//resource "vault_aws_secret_backend" "aws" {
//path = "%s"
//description = "Obtain AWS credentials."
//access_key = "%s"
//secret_key = "%s"
//region = "%s"
//}

const testAWSStaticDataResource = `
resource "vault_aws_secret_backend" "aws" {
	path = "%s"
	description = "Obtain AWS credentials."
}

resource "vault_aws_secret_backend_static_role" "role" {
	mount = vault_aws_secret_backend.aws.path
	name = "test"
	username = "%s"
	rotation_period = "3600"
}

data "vault_aws_static_access_credentials" "creds" {
	mount = vault_aws_secret_backend.aws.path
	name = vault_aws_secret_backend_static_role.role.name
}`

func testAWSStaticDataSourceConfig(mount, username string) string {
	return fmt.Sprintf(testAWSStaticDataResource, mount, username)
}
