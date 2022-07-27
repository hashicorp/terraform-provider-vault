package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestManagedKeys(t *testing.T) {
	namePrefix := acctest.RandomWithPrefix("aws-keys")
	name0 := namePrefix + "-0"
	name1 := namePrefix + "-1"

	resourceName := "vault_managed_keys.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestEntPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			//{
			//	Config: testManagedKeysConfig(pathAWS, fmt.Sprintf("%s-2", pathAWS)),
			//	Check: resource.ComposeTestCheckFunc(
			//		resource.TestCheckResourceAttr(resourceName, "aws.*.`name`", pathAWS),
			//		resource.TestCheckResourceAttr(resourceName, "aws.0.access_key", "ASIAKBASDADA09090"),
			//		resource.TestCheckResourceAttr(resourceName, "aws.0.secret_key", "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"),
			//		resource.TestCheckResourceAttr(resourceName, "aws.0.key_bits", "2048"),
			//		resource.TestCheckResourceAttr(resourceName, "aws.0.key_type", "RSA"),
			//		resource.TestCheckResourceAttr(resourceName, "aws.0.kms_key", "alias/test_identifier_string"),
			//		resource.TestCheckResourceAttrSet(resourceName, "aws.0.uuid"),
			//	),
			//},
			//{
			//	Config: testManagedKeysConfig(pathAWS, fmt.Sprintf("%s-2", pathAWS)),
			//	Check: resource.ComposeTestCheckFunc(
			//		resource.TestCheckResourceAttr(resourceName, "aws.1.name", fmt.Sprintf("%s-2", pathAWS)),
			//		resource.TestCheckResourceAttr(resourceName, "aws.1.access_key", "ASIAKBASDADA09090"),
			//		resource.TestCheckResourceAttr(resourceName, "aws.1.secret_key", "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"),
			//		resource.TestCheckResourceAttr(resourceName, "aws.1.key_bits", "2048"),
			//		resource.TestCheckResourceAttr(resourceName, "aws.1.key_type", "RSA"),
			//		resource.TestCheckResourceAttr(resourceName, "aws.1.kms_key", "alias/test_identifier_string_2"),
			//		resource.TestCheckResourceAttrSet(resourceName, "aws.1.uuid"),
			//	),
			//},
			{
				Config: testManagedKeysConfig(name0, name1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "aws.#", "2"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// ImportStateVerifyIgnore: []string{"aws.0.access_key", "aws.0.secret_key"},
			},
		},
	})
}

func testManagedKeysConfig(pathAWS1, pathAWS2 string) string {
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

  aws {
    name       = "%s"
    access_key = "ASIAKBASDADA09090"
    secret_key = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
    key_bits   = "2048"
    key_type   = "RSA"
    kms_key    = "alias/test_identifier_string_2"
  }
}
`, pathAWS1, pathAWS2)
}
