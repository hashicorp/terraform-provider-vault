package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"
)

func TestAccDataSourceAWSStaticCredentials(t *testing.T) {
	//mountPath := acctest.RandomWithPrefix("tf-test-aws-static")
	//accessKey, secretKey := testutil.GetTestAWSCreds(t) // from the environment, causes test to skip if unset

	resource.Test(t, resource.TestCase{
		IsUnitTest: false,
		PreCheck: func() {
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAWSStaticDataSourceConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_aws_static_access_credentials.creds", consts.FieldAWSAccessKeyID, "fail"),
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
	region = "%s"
}

resource "vault_aws_secret_backend_static_role" "role" {
	backend = vault_aws_secret_backend.aws.path
	name = "test"
	username = "jane-doe"
	rotation_period = "1h"
}

data "vault_aws_static_access_credentials" "test" {
	backend = vault_aws_secret_backend.aws.path
	role = vault_aws_secret_backend_role.role.name
}`

//, mountPath, accessKey, secretKey, region)`

func testAWSStaticDataSourceConfig() string {
	return ""
}
