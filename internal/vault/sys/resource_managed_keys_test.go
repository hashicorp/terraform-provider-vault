// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

/*
func TestManagedKeys(t *testing.T) {
	namePrefix := acctest.RandomWithPrefix("aws-keys")
	name0 := namePrefix + "-0"
	name1 := namePrefix + "-1"

	resourceName := "vault_managed_keys.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					// Create a managed key in Vault
					client, err := provider.GetClient("", vault.testProvider.Meta())

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
					client := vault.testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

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
					client := vault.testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

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
*/

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

	namePrefix := acctest.RandomWithPrefix("pkcs-keys")
	name0 := namePrefix + "-0"
	name1 := namePrefix + "-1"
	resourceName := "vault_managed_keys.test"

	library, slot, pin := testutil.GetTestPKCSCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a resource with name0
				Config: testManagedKeysConfig_pkcs(name0, library, slot, pin, "label1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "pkcs.*",
						map[string]string{
							consts.FieldName:             name0,
							consts.FieldKeyBits:          "4096",
							consts.FieldLibrary:          library,
							consts.FieldSlot:             slot,
							consts.FieldPin:              pin,
							consts.FieldKeyLabel:         "label1",
							consts.FieldMechanism:        "0x0001",
							consts.FieldAnyMount:         "true",
							consts.FieldAllowReplaceKey:  "false",
							consts.FieldAllowStoreKey:    "false",
							consts.FieldAllowGenerateKey: "false",
						},
					),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"pkcs.0.pin"},
			},
			{
				// Update name0 to have a new label
				Config: testManagedKeysConfig_pkcs(name0, library, slot, pin, "label2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "pkcs.*",
						map[string]string{
							consts.FieldName:             name0,
							consts.FieldKeyBits:          "4096",
							consts.FieldLibrary:          library,
							consts.FieldSlot:             slot,
							consts.FieldPin:              pin,
							consts.FieldKeyLabel:         "label2",
							consts.FieldMechanism:        "0x0001",
							consts.FieldAnyMount:         "true",
							consts.FieldAllowReplaceKey:  "false",
							consts.FieldAllowStoreKey:    "false",
							consts.FieldAllowGenerateKey: "false",
						},
					),
				),
			},
			{
				// Replace existing config block with a new one having a different name.
				Config: testManagedKeysConfig_pkcs(name1, library, slot, pin, "label2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "pkcs.*",
						map[string]string{
							consts.FieldName:             name1,
							consts.FieldKeyBits:          "4096",
							consts.FieldLibrary:          library,
							consts.FieldSlot:             slot,
							consts.FieldPin:              pin,
							consts.FieldKeyLabel:         "label2",
							consts.FieldMechanism:        "0x0001",
							consts.FieldAnyMount:         "true",
							consts.FieldAllowReplaceKey:  "false",
							consts.FieldAllowStoreKey:    "false",
							consts.FieldAllowGenerateKey: "false",
						},
					),
				),
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

func testManagedKeysConfig_pkcs(name, library, slot, pin, label string) string {
	return fmt.Sprintf(`
resource "vault_managed_keys" "test" {
  pkcs {
    name               = "%s"
    library            = "%s"
    key_label          = "%s"
    key_bits           = "4096"
    slot               = "%s"
    pin                = "%s"
    mechanism          = "0x0001"
    any_mount          = true
  }
}
`, name, library, label, slot, pin)
}
