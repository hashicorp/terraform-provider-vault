package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"
)

func TestAccAWSSecretBackendStaticRole(t *testing.T) {
	//mount := acctest.RandomWithPrefix("tf-aws-static")
	//name := acctest.RandomWithPrefix("tf-role")
	//username := "jane-doe"
	//rotationPeriod := "15m"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretBackendStaticRoleConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_aws_secret_backend_static_role.role", "rotation_period", "bad"),
				),
			},
		},
	})
}

const testAWSSecretBackendStaticRoleConfig = `
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
}`
