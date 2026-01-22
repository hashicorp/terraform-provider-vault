// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
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
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
							"usages.#":            "2",
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
					"aws.0.usages.#", "aws.0.usages.0", "aws.0.usages.1",
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
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      testManagedKeysConfig_pkcs_nokeyidorlabel(name, library, slot, pin),
				ExpectError: regexp.MustCompile("at least one of key_id or key_label must be provided"),
			},
			{
				Config: testManagedKeysConfig_pkcs(name, library, slot, pin),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "pkcs.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.library", library),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.key_label", "kms-intermediate"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.key_bits", "4096"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.slot", slot),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.pin", pin),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.mechanism", "1"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.max_parallel", "4"),
					resource.TestCheckResourceAttr(resourceName, "pkcs.0.usages.#", "3"),
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
    usages     = ["sign", "verify"]
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
    key_bits           = "4096"
    slot               = "%s"
    pin                = "%s"
    mechanism          = "0x0001"
    max_parallel       = 4
    usages             = ["sign", "verify", "encrypt"]
  }
}
`, name, library, slot, pin)
}

func testManagedKeysConfig_pkcs_nokeyidorlabel(name, library, slot, pin string) string {
	return fmt.Sprintf(`
resource "vault_managed_keys" "test" {
  pkcs {
    name               = "%s"
    library            = "%s"
    key_bits           = "4096"
    slot               = "%s"
    pin                = "%s"
    mechanism          = "0x0001"
  }
}
`, name, library, slot, pin)
}

// The following test requires a GCP Cloud KMS to be set up and needs the following
// environment variables to operate successfully:
// * GCP_CREDENTIALS - Path to GCP credentials JSON file
// * GCP_PROJECT - GCP project ID
// * GCP_KEY_RING - GCP KMS key ring name
// * GCP_REGION - GCP region
// * TF_ACC_LOCAL=1
//
// The final variable specifies that this test can only be run locally
func TestManagedKeysGCP(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "TF_ACC_LOCAL")

	name := acctest.RandomWithPrefix("gcp-keys")
	resourceName := "vault_managed_keys.test"

	credentials, project := testutil.GetTestGCPCreds(t)
	keyRing := testutil.GetTestGCPKeyRing(t)
	region := testutil.GetTestGCPRegion(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testManagedKeysConfig_gcp(name, credentials, project, keyRing, region),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "gcp.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "gcp.0.name", name),
					resource.TestCheckResourceAttr(resourceName, "gcp.0.project", project),
					resource.TestCheckResourceAttr(resourceName, "gcp.0.key_ring", keyRing),
					resource.TestCheckResourceAttr(resourceName, "gcp.0.crypto_key", "test-crypto-key"),
					resource.TestCheckResourceAttr(resourceName, "gcp.0.algorithm", "ec_sign_p256_sha256"),
					resource.TestCheckResourceAttr(resourceName, "gcp.0.max_parallel", "4"),
					resource.TestCheckResourceAttr(resourceName, "gcp.0.usages.#", "2"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"gcp.0.credentials", "gcp.0.usages.#", "gcp.0.usages.0", "gcp.0.usages.1"},
			},
		},
	})
}

func testManagedKeysConfig_gcp(name, credentials, project, keyRing, region string) string {
	return fmt.Sprintf(`
resource "vault_managed_keys" "test" {
  gcp {
    name               = "%s"
    credentials        = "%s"
    project            = "%s"
    key_ring           = "%s"
    region             = "%s"
    crypto_key         = "test-crypto-key"
    algorithm          = "ec_sign_p256_sha256"
    max_parallel       = 4
    usages             = ["sign", "verify"]
  }
}
`, name, credentials, project, keyRing, region)
}
