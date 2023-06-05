package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"testing"
)

func TestAccAWSSecretBackendStaticRole(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-aws-static")
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	//name := acctest.RandomWithPrefix("tf-role")
	username := testutil.SkipTestEnvUnset(t, "AWS_STATIC_USER")[0]
	//rotationPeriod := "15m"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			//SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAWSStaticReourceConfig(mount, accessKey, secretKey, username),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_static_role.role", "name", "test"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_static_role.role", "username", "vault-static-roles-test"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_static_role.role", "rotation_period", "3600"),
				),
			},
		},
	})
}

const testAWSStaticResource = `
resource "vault_aws_secret_backend" "aws" {
	path = "%s"
	description = "Obtain AWS credentials."
}

resource "vault_aws_secret_backend_static_role" "role" {
	mount = vault_aws_secret_backend.aws.path
	name = "test"
	username = "%s"
	rotation_period = "3600"
}`

//, mountPath, accessKey, secretKey, region)`

func testAWSStaticReourceConfig(mount, access, secret, username string) string {
	return fmt.Sprintf(testAWSStaticResource, mount, username)
}
