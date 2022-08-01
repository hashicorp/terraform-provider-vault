package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"

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
			{
				Config: testManagedKeysConfig_basic(name0, name1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "aws.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "aws.*",
						map[string]string{
							consts.FieldName:         name0,
							consts.FieldKeyBits:      "2048",
							consts.FieldKeyType:      "RSA",
							consts.FieldKMSKey:       "alias/test_identifier_string",
							consts.FieldAWSAccessKey: "ASIAKBASDADA09090",
							consts.FieldAWSSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "aws.*",
						map[string]string{
							consts.FieldName:         name1,
							consts.FieldKeyBits:      "4096",
							consts.FieldKeyType:      "RSA",
							consts.FieldKMSKey:       "alias/test_identifier_string_2",
							consts.FieldAWSAccessKey: "ASIAKBASDADA09090",
							consts.FieldAWSSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						},
					),
				),
			},
			// This test removes one of the managed keys from the set
			// and also updates the name for the other remaining key
			// Tests: ForceNew on Name + Deletion of removed keys
			{
				Config: testManagedKeysConfig_updated(name0),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "aws.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "aws.*",
						map[string]string{
							consts.FieldName:         name0,
							consts.FieldKeyBits:      "4096",
							consts.FieldKeyType:      "RSA",
							consts.FieldKMSKey:       "alias/test_identifier_string_2",
							consts.FieldAWSAccessKey: "ASIAKBASDADA09090",
							consts.FieldAWSSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						},
					),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"aws.0.access_key", "aws.1.access_key",
					"aws.0.secret_key", "aws.1.secret_key",
				},
			},
		},
	})
}

func testManagedKeysConfig_basic(name0, name1 string) string {
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
    key_bits   = "4096"
    key_type   = "RSA"
    kms_key    = "alias/test_identifier_string_2"
  }
}
`, name0, name1)
}

func testManagedKeysConfig_updated(name string) string {
	return fmt.Sprintf(`
resource "vault_managed_keys" "test" {
  aws {
    name       = "%s"
    access_key = "ASIAKBASDADA09090"
    secret_key = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
    key_bits   = "4096"
    key_type   = "RSA"
    kms_key    = "alias/test_identifier_string_2"
  }
}
`, name)
}
