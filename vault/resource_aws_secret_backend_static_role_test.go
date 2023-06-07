package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"testing"
)

func TestAccAWSSecretBackendStaticRole(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-aws-static")
	a, s := testutil.GetTestAWSCreds(t)
	username := testutil.SkipTestEnvUnset(t, "AWS_STATIC_USER")[0]

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAWSStaticReourceConfig(mount, a, s, username),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_static_role.role", "name", "test"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_static_role.role", "username", "vault-static-roles-test"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_static_role.role", "rotation_period", "3600"),
				),
			},
			testutil.GetImportTestStep("vault_aws_secret_backend_static_role.role", false, nil),
		},
	})
}

const testAWSStaticResource = `
resource "vault_aws_secret_backend" "aws" {
	path = "%s"
	description = "Obtain AWS credentials."
#	access_key = "%s"
#	secret_key = "%s"
#	region = "%s"
}

resource "vault_aws_secret_backend_static_role" "role" {
	backend = vault_aws_secret_backend.aws.path
	name = "test"
	username = "%s"
	rotation_period = "3600"
}`

func testAWSStaticReourceConfig(mount, access, secret, username string) string {
	return fmt.Sprintf(testAWSStaticResource, mount, access, secret, "us-east-1", username)
}
