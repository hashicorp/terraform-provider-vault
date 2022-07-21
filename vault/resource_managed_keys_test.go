package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestManagedKeys(t *testing.T) {
	pathAWS := acctest.RandomWithPrefix("aws-keys")
	pathAzure := acctest.RandomWithPrefix("azure-keys")

	resourceName := "vault_managed_keys.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestEntPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testManagedKeysConfig(pathAWS, pathAzure),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "aws.0.name", pathAWS),
					resource.TestCheckResourceAttr(resourceName, "aws.0.access_key", "ASIAKBASDADA09090"),
					resource.TestCheckResourceAttr(resourceName, "aws.0.secret_key", "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"),
					resource.TestCheckResourceAttr(resourceName, "aws.0.key_bits", "2048"),
					resource.TestCheckResourceAttr(resourceName, "aws.0.key_type", "RSA"),
					resource.TestCheckResourceAttr(resourceName, "aws.0.kms_key", "alias/test_identifier_string"),
					resource.TestCheckResourceAttrSet(resourceName, "aws.0.uuid"),
				),
			},
		},
	})
}

func testManagedKeysConfig(pathAWS, pathAzure string) string {
	return fmt.Sprintf(`
resource "vault_managed_keys" "test" {

  aws {
    name       = "%s"
    access_key = "ASIAKBASDADA09090"
    secret_key = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
    key_bits   = "2048"
    key_type   = "RSA"
    kms_key    = "alias/test_identifier_string"
  }
}
`, pathAWS)
}
