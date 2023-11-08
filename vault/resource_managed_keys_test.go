// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestManagedKeys(t *testing.T) {
	namePrefix := acctest.RandomWithPrefix("aws-keys")
	name0 := namePrefix + "-0"
	name1 := namePrefix + "-1"

	resourceName := "vault_managed_keys.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					// Create a managed key in Vault
					client, err := provider.GetClient("", testProvider.Meta())

					data := map[string]interface{}{
						consts.FieldAccessKey: "ASIAKBASDADA09090",
						consts.FieldSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						consts.FieldKeyBits:   "2048",
						consts.FieldKeyType:   "RSA",
						consts.FieldKMSKey:    "alias/test_identifier_string",
					}

					p := getManagedKeysPath(kmsTypeAWS, name0)
					_, err = client.Logical().Write(p, data)
					if err != nil {
						t.Fatalf("failed to create Vault managed key %q, err=%s", p, err)
					}
				},
				Config:      testManagedKeysConfig_basic(name0, name1),
				ExpectError: regexp.MustCompile("managed keys already exist in Vault; use 'terraform import' instead"),
			},
			{
				PreConfig: func() {
					// Delete previously configured managed key from Vault
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					p := getManagedKeysPath(kmsTypeAWS, name0)
					_, err := client.Logical().Delete(p)
					if err != nil {
						t.Fatalf("manual cleanup required, failed to delete Vault managed key %q, err=%s", p, err)
					}
				},
				Config: testManagedKeysConfig_basic(name0, name1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "aws.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "aws.*",
						map[string]string{
							consts.FieldName:      name0,
							consts.FieldKeyBits:   "2048",
							consts.FieldKeyType:   "RSA",
							consts.FieldKMSKey:    "alias/test_identifier_string",
							consts.FieldAccessKey: "ASIAKBASDADA09090",
							consts.FieldSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						},
					),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "aws.*",
						map[string]string{
							consts.FieldName:      name1,
							consts.FieldKeyBits:   "4096",
							consts.FieldKeyType:   "RSA",
							consts.FieldKMSKey:    "alias/test_identifier_string_2",
							consts.FieldAccessKey: "ASIAKBASDADA09090",
							consts.FieldSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						},
					),
				),
			},
			// This test removes one of the managed keys from the set
			// and also updates the name for the other remaining key
			// Tests: new managed key is created on Name change
			// + Deletion of previously named keys
			{
				Config: testManagedKeysConfig_updated(name0),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "aws.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "aws.*",
						map[string]string{
							consts.FieldName:      name0,
							consts.FieldKeyBits:   "4096",
							consts.FieldKeyType:   "RSA",
							consts.FieldKMSKey:    "alias/test_identifier_string_2",
							consts.FieldAccessKey: "ASIAKBASDADA09090",
							consts.FieldSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						},
					),
				),
			},
			// test out-of-band changes and UUID update
			{
				PreConfig: func() {
					// Delete previously configured managed key from Vault
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					p := getManagedKeysPath(kmsTypeAWS, name0)
					_, err := client.Logical().Delete(p)
					if err != nil {
						t.Fatalf("manual cleanup required, failed to delete Vault managed key %q, err=%s", p, err)
					}

					// Recreate w/ same name; forces UUID update out-of-band
					data := map[string]interface{}{
						consts.FieldAccessKey: "ASIAKBASDADA09090",
						consts.FieldSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						consts.FieldKeyBits:   "4096",
						consts.FieldKeyType:   "RSA",
						consts.FieldKMSKey:    "alias/test_identifier_string_2",
					}

					_, err = client.Logical().Write(p, data)
					if err != nil {
						t.Fatalf("failed to create Vault managed key %q, err=%s", p, err)
					}
				},
				Config: testManagedKeysConfig_updated(name0),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "aws.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "aws.*",
						map[string]string{
							consts.FieldName:      name0,
							consts.FieldKeyBits:   "4096",
							consts.FieldKeyType:   "RSA",
							consts.FieldKMSKey:    "alias/test_identifier_string_2",
							consts.FieldAccessKey: "ASIAKBASDADA09090",
							consts.FieldSecretKey: "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						},
					),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"aws.0.access_key", "aws.0.secret_key",
				},
			},
		},
	})
}

// The following test requires a Vault server to be set up with a specific server configuration
// (kms_library needs to be defined). We need not dedicate an entire server setup just for one
// test, and hence this test is meant to be run locally
//
// The following test requires a PKCS#11 key to be set up and needs the following
// environment variables to operate successfully:
// * PKCS_KEY_LIBRARY
// * PKCS_KEY_SLOT
// * PKCS_KEY_PIN
// * TF_ACC_LOCAL=1
//
// The final variable specifies that this test can only be run locally
func TestManagedKeysPKCS(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "TF_ACC_LOCAL")

	name := acctest.RandomWithPrefix("pkcs-keys")
	resourceName := "vault_managed_keys.test"

	library, slot, pin := testutil.GetTestPKCSCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testManagedKeysConfig_pkcs(name, library, slot, pin),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "pkcs.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.library", library),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.key_label", "kms-intermediate"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.key_id", "kms-intermediate"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.key_bits", "4096"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.slot", slot),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.pin", pin),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.mechanism", "1"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"pkcs.0.pin", "pkcs.0.key_id"},
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

func testManagedKeysConfig_pkcs(name, library, slot, pin string) string {
	return fmt.Sprintf(`
resource "vault_managed_keys" "test" {
  pkcs {
    name               = "%s"
    library            = "%s"
    key_label          = "kms-intermediate"
    key_id             = "kms-intermediate"
    key_bits           = "4096"
    slot               = "%s"
    pin                = "%s"
    mechanism          = "0x0001"
  }
}
`, name, library, slot, pin)
}
