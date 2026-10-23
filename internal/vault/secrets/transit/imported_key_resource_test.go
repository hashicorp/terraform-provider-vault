// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"regexp"
	"testing"

	version "github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	vaultclient "github.com/hashicorp/vault/api"
)

type transitImportedKeyFields struct {
	// directMount uses a literal mount path and does not declare vault_mount.test, for tests
	// that mount transit themselves (e.g. to read the wrapping key before the config runs).
	directMount          bool
	mount                string
	name                 string
	keyType              string
	publicKey            string
	ciphertext           string
	ciphertextWOVersion  int64
	version              int64
	importVersionType    string
	hashFunction         string
	allowRotation        bool
	exportable           bool
	allowPlaintextBackup bool
	autoRotatePeriod     *int64
	minDecryptionVersion int64
	minEncryptionVersion int64
	deletionAllowed      bool
}

func int64Ptr(v int64) *int64 {
	return &v
}

// TestAccTransitImportedKey_publicKey validates the lifecycle of importing a public key:
//   - Step 1: Create with required fields only (deletion_allowed and allow_rotation default to false)
//   - Step 2: In-place update of tunable configuration parameters (/config), enabling deletion_allowed
//   - Step 3: Change allow_rotation to true -> forces resource replacement (destroy + recreate)
//   - Step 4: Import state verification
func TestAccTransitImportedKey_publicKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	pubKey := generateTestECDSAPublicKeyPEM(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with required fields only (testing Vault defaults).
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:     mount,
					name:      keyName,
					keyType:   "ecdsa-p256",
					publicKey: pubKey,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "type", "ecdsa-p256"),
					resource.TestCheckResourceAttr(resourceAddress, "imported_key", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "allow_rotation", "false"),
					resource.TestCheckResourceAttr(resourceAddress, "deletion_allowed", "false"),
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "false"),
					resource.TestCheckResourceAttr(resourceAddress, "allow_plaintext_backup", "false"),
					resource.TestCheckResourceAttr(resourceAddress, "auto_rotate_period", "0"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "min_decryption_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "min_encryption_version", "0"),
					resource.TestCheckResourceAttr(resourceAddress, "min_available_version", "0"),
					resource.TestCheckResourceAttr(resourceAddress, "supports_signing", "true"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: In-place update to tunable configuration parameters (/config), enabling deletion_allowed
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:                mount,
					name:                 keyName,
					keyType:              "ecdsa-p256",
					publicKey:            pubKey,
					autoRotatePeriod:     int64Ptr(3600),
					minDecryptionVersion: 1,
					minEncryptionVersion: 1,
					deletionAllowed:      true,
					exportable:           true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "auto_rotate_period", "3600"),
					resource.TestCheckResourceAttr(resourceAddress, "min_decryption_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "min_encryption_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "imported_key", "true"),
					// A tunable-only change must not import another key version.
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
					// latest_version_type is only populated by Vault >= 2.1
					func(s *terraform.State) error {
						if acctestutil.IsAPIVersionGTE(version.Must(version.NewVersion("2.1.0"))) {
							return resource.TestCheckResourceAttr(resourceAddress, "latest_version_type", "ecdsa-p256")(s)
						}
						return nil
					},
				),
			},
			// Step 3: Change allow_rotation -> forces resource replacement (destroy + recreate).
			// This succeeds because deletion_allowed was set to true in Step 2.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					publicKey:       pubKey,
					allowRotation:   true,
					deletionAllowed: true,
					exportable:      true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionReplace),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "allow_rotation", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "imported_key_allow_rotation", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "deletion_allowed", "true"),
				),
			},
			// Step 4: Import state verification
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransitImportedKeyStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				// These are all values that are not returned by vault.
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertextWO,
					consts.FieldCiphertextWOVersion,
					consts.FieldVersion,
					consts.FieldContext,
					consts.FieldPublicKey,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

// TestAccTransitImportedKey_wrappedKey validates importing wrapped symmetric key material and
// the ciphertext_wo / ciphertext_wo_version gating:
//   - Step 1: ciphertext_wo without ciphertext_wo_version -> validation error
//   - Step 2: Create with wrapped AES-256 ciphertext (defaults only)
//   - Step 3: Edit only a tunable with ciphertext_wo still in config -> ciphertext must NOT be
//     re-sent (Vault would append a duplicate version, so latest_version must stay at 1)
//   - Step 4: Bump ciphertext_wo_version with new ciphertext -> in-place update importing version 2
//   - Step 5: Import state verification
func TestAccTransitImportedKey_wrappedKey(t *testing.T) {
	acctestutil.SkipTestAcc(t)
	acctestutil.TestAccPreCheck(t)

	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	cli := acctestutil.TestProvider.Meta().(*provider.ProviderMeta).MustGetClient()
	err := cli.Sys().Mount(mount, &vaultclient.MountInput{Type: "transit"})
	if err != nil {
		t.Fatalf("failed to mount transit: %v", err)
	}
	defer cli.Sys().Unmount(mount)

	secret, err := cli.Logical().Read(mount + "/wrapping_key")
	if err != nil || secret == nil {
		t.Fatalf("failed to read wrapping key: %v", err)
	}
	pubKey, ok := secret.Data["public_key"].(string)
	if !ok {
		t.Fatalf("failed to extract public key from wrapping key endpoint")
	}

	rawAESKey1 := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawAESKey1); err != nil {
		t.Fatalf("failed to generate random AES key 1: %v", err)
	}
	rawAESKey2 := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawAESKey2); err != nil {
		t.Fatalf("failed to generate random AES key 2: %v", err)
	}

	ciphertext1 := createTransitBYOKCiphertext(t, pubKey, rawAESKey1)
	ciphertext2 := createTransitBYOKCiphertext(t, pubKey, rawAESKey2)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			// Step 1: ciphertext_wo must be paired with ciphertext_wo_version.
			{
				Config: fmt.Sprintf(`
resource "vault_transit_secret_backend_imported_key" "test" {
		mount            = %q
		name             = %q
		type             = "aes256-gcm96"
		deletion_allowed = true
		ciphertext_wo    = %q
}
`, mount, keyName, ciphertext1),
				ExpectError: regexp.MustCompile(`ciphertext_wo_version`),
			},
			// Step 2: Create with initial wrapped ciphertext
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "aes256-gcm96",
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "type", "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceAddress, "imported_key", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "supports_encryption", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "supports_decryption", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: ciphertext_wo stays in config but only a tunable changes. ciphertext_wo_version
			// is unchanged, so the ciphertext must not be re-sent. Vault appends a duplicate version
			// when the same ciphertext is posted again, so latest_version staying at 1 proves it.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "aes256-gcm96",
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
					exportable:          true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "1"),
				),
			},
			// Step 4: New ciphertext with a bumped ciphertext_wo_version -> in-place update
			// that imports the ciphertext as version 2.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "aes256-gcm96",
					ciphertext:          ciphertext2,
					ciphertextWOVersion: 2,
					exportable:          true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "type", "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "2"),
				),
			},
			// Step 5: ciphertext_wo and ciphertext_wo_version removed from config -> no plan change,
			// no new version. The key material is only needed when it is imported.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:     true,
					deletionAllowed: true,
					mount:           mount,
					name:            keyName,
					keyType:         "aes256-gcm96",
					exportable:      true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "2"),
				),
			},
			// Step 6: Import state verification
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransitImportedKeyStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertextWO,
					consts.FieldCiphertextWOVersion,
					consts.FieldVersion,
					consts.FieldContext,
					consts.FieldPublicKey,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

// testAccTransitImportedKeyWrappingKey mounts transit and returns the mount's public
// wrapping key, which is used to build wrapped ciphertexts for the BYOK tests.
func testAccTransitImportedKeyWrappingKey(t *testing.T, mount string) string {
	t.Helper()

	cli := acctestutil.TestProvider.Meta().(*provider.ProviderMeta).MustGetClient()
	if err := cli.Sys().Mount(mount, &vaultclient.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("failed to mount transit: %v", err)
	}
	t.Cleanup(func() { cli.Sys().Unmount(mount) })

	secret, err := cli.Logical().Read(mount + "/wrapping_key")
	if err != nil || secret == nil {
		t.Fatalf("failed to read wrapping key: %v", err)
	}
	wrappingKey, ok := secret.Data["public_key"].(string)
	if !ok {
		t.Fatalf("failed to extract public key from wrapping key endpoint")
	}
	return wrappingKey
}

// TestAccTransitImportedKey_backfillPrivateKey validates the version argument by attaching a
// private key to an older, public-key-only version:
//   - Step 1: Create with public_key only (version 1)
//   - Step 2: Change public_key -> version 2 is imported
//   - Step 3: Add ciphertext_wo wrapping the private key for version 1 with version = 1 ->
//     Vault attaches the private key to version 1 instead of creating version 3
func TestAccTransitImportedKey_backfillPrivateKey(t *testing.T) {
	acctestutil.SkipTestAcc(t)
	acctestutil.TestAccPreCheck(t)

	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	wrappingKey := testAccTransitImportedKeyWrappingKey(t, mount)
	pubKey1, privKey1 := generateTestECDSAKeyPair(t)
	pubKey2 := generateTestECDSAPublicKeyPEM(t)
	privKey1Ciphertext := createTransitBYOKCiphertext(t, wrappingKey, privKey1)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			// Step 1: public key only.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:     true,
					deletionAllowed: true,
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					publicKey:       pubKey1,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "1"),
				),
			},
			// Step 2: a new public_key imports version 2.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:     true,
					deletionAllowed: true,
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					publicKey:       pubKey2,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "2"),
				),
			},
			// Step 3: attach the private key to version 1. latest_version must stay at 2.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "ecdsa-p256",
					publicKey:           pubKey2,
					ciphertext:          privKey1Ciphertext,
					ciphertextWOVersion: 1,
					version:             1,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "2"),
				),
			},
		},
	})
}

// TestAccTransitImportedKey_hashFunctionWithCiphertext validates that hash_function is sent
// with every ciphertext import, not only when it changes. Both ciphertexts are wrapped with
// SHA512, so hash_function does not change between steps; if it were omitted on the bump,
// Vault would default to SHA256 and fail to unwrap the ciphertext.
//   - Step 1: Create with a SHA512-wrapped ciphertext and hash_function = SHA512
//   - Step 2: Bump ciphertext_wo_version with a new SHA512-wrapped ciphertext -> version 2
func TestAccTransitImportedKey_hashFunctionWithCiphertext(t *testing.T) {
	acctestutil.SkipTestAcc(t)
	acctestutil.TestAccPreCheck(t)

	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	wrappingKey := testAccTransitImportedKeyWrappingKey(t, mount)

	rawAESKey1 := make([]byte, 32)
	rawAESKey2 := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawAESKey1); err != nil {
		t.Fatalf("failed to generate random AES key 1: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, rawAESKey2); err != nil {
		t.Fatalf("failed to generate random AES key 2: %v", err)
	}
	ciphertext1 := createTransitBYOKCiphertextWithHash(t, wrappingKey, rawAESKey1, "SHA512")
	ciphertext2 := createTransitBYOKCiphertextWithHash(t, wrappingKey, rawAESKey2, "SHA512")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "aes256-gcm96",
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
					hashFunction:        "SHA512",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "hash_function", "SHA512"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
				),
			},
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "aes256-gcm96",
					ciphertext:          ciphertext2,
					ciphertextWOVersion: 2,
					hashFunction:        "SHA512",
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "2"),
				),
			},
		},
	})
}

// TestAccTransitImportedKey_ciphertextWOVersionRequiresCiphertext validates the only
// schema-level check left on the key material arguments: ciphertext_wo_version must be
// paired with ciphertext_wo. Everything else (for example no key material at all) is
// left for Vault to reject.
func TestAccTransitImportedKey_ciphertextWOVersionRequiresCiphertext(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_transit_secret_backend_imported_key" "test" {
  mount                 = %q
  name                  = %q
  type                  = "aes256-gcm96"
  ciphertext_wo_version = 1
}
`, mount, keyName),
				ExpectError: regexp.MustCompile(`ciphertext_wo`),
			},
		},
	})
}

// TestAccTransitImportedKey_keyMaterialRemovedFromConfig validates that key material is only
// needed when it is imported: once the key exists, public_key can be dropped from config
// and the resource keeps managing its tunables without importing another key version.
func TestAccTransitImportedKey_keyMaterialRemovedFromConfig(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	pubKey := generateTestECDSAPublicKeyPEM(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					publicKey:       pubKey,
					deletionAllowed: true,
				}),
				Check: resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
			},
			// public_key removed from config and a tunable changed: in-place update, no new version.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					deletionAllowed: true,
					exportable:      true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "1"),
				),
			},
		},
	})
}

// TestAccTransitImportedKey_optionalFields validates setting optional fields at import
func TestAccTransitImportedKey_optionalFields(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	pubKey := generateTestRSAPublicKeyPEM(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:                mount,
					name:                 keyName,
					keyType:              "rsa-2048",
					publicKey:            pubKey,
					exportable:           true,
					allowPlaintextBackup: true,
					allowRotation:        true,
					hashFunction:         "SHA384",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "type", "rsa-2048"),
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "allow_plaintext_backup", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "allow_rotation", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "hash_function", "SHA384"),
					resource.TestCheckResourceAttr(resourceAddress, "imported_key", "true"),
				),
			},
			// Step 2: In-place update of config fields (auto_rotate_period, min_decryption_version, min_encryption_version, deletion_allowed)
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:                mount,
					name:                 keyName,
					keyType:              "rsa-2048",
					publicKey:            pubKey,
					exportable:           true,
					allowPlaintextBackup: true,
					allowRotation:        true,
					hashFunction:         "SHA384",
					autoRotatePeriod:     int64Ptr(3600),
					minDecryptionVersion: 1,
					minEncryptionVersion: 1,
					deletionAllowed:      true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "auto_rotate_period", "3600"),
					resource.TestCheckResourceAttr(resourceAddress, "min_decryption_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "min_encryption_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "allow_plaintext_backup", "true"),
				),
			},
			// Step 3: In-place update auto_rotate_period back to 0
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:                mount,
					name:                 keyName,
					keyType:              "rsa-2048",
					publicKey:            pubKey,
					exportable:           true,
					allowPlaintextBackup: true,
					allowRotation:        true,
					hashFunction:         "SHA384",
					autoRotatePeriod:     int64Ptr(0),
					minDecryptionVersion: 1,
					minEncryptionVersion: 1,
					deletionAllowed:      true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "auto_rotate_period", "0"),
					resource.TestCheckResourceAttr(resourceAddress, "min_decryption_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "min_encryption_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "allow_plaintext_backup", "true"),
				),
			},
			// Step 4: Import state verification
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransitImportedKeyStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertextWO,
					consts.FieldCiphertextWOVersion,
					consts.FieldVersion,
					consts.FieldContext,
					consts.FieldPublicKey,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

// TestAccTransitImportedKey_versionImportedDuringUpdate verifies that computed
// attributes that change when a key version is imported (latest_version, keys,
// min_available_version) are not planned with UseStateForUnknown. Otherwise,
// importing a key version in the same Update as a /config change makes Vault
// return a different value than the plan and Terraform fails with
// "inconsistent result after apply".
//
//   - Step 1: Create the key at version 1.
//   - Step 2: Change public_key and a tunable in the same apply: version 2 is
//     imported and /config is updated.
//   - Step 3: Change min_decryption_version alone: no new version is imported.
func TestAccTransitImportedKey_versionImportedDuringUpdate(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	pubKey1 := generateTestECDSAPublicKeyPEM(t)
	pubKey2 := generateTestECDSAPublicKeyPEM(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the key at version 1.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					publicKey:       pubKey1,
					deletionAllowed: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "false"),
				),
			},
			// Step 2: Import version 2 (public_key change) and update /config in the same apply.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					publicKey:       pubKey2,
					deletionAllowed: true,
					exportable:      true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "true"),
					// Values that changed due to the version import, not the /config update.
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "2"),
					// Unchanged by a same-type version import; asserted to document that.
					resource.TestCheckResourceAttr(resourceAddress, "min_available_version", "0"),
				),
			},
			// Step 3: Change min_decryption_version alone; no new version is imported.
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:                mount,
					name:                 keyName,
					keyType:              "ecdsa-p256",
					publicKey:            pubKey2,
					deletionAllowed:      true,
					exportable:           true,
					minDecryptionVersion: 2,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "min_decryption_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					// Vault only returns key versions >= min_decryption_version, so version 1
					// drops out of keys even though it still exists. latest_version staying at 2
					// shows no new version was imported.
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "1"),
				),
			},
		},
	})
}

// TestAccTransitImportedKey_importVersionType validates importing a key version of a different type
// (crypto agility, Vault Enterprise only):
//   - Step 1: Create an ecdsa-p256 key from a public key
//   - Step 2: Import an ecdsa-p384 public key as version 2 with import_version_type -> type stays
//     ecdsa-p256 and latest_version_type becomes ecdsa-p384
func TestAccTransitImportedKey_importVersionType(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	pubKeyP256 := generateTestECDSAPublicKeyPEM(t)
	pubKeyP384 := generateTestECDSAP384PublicKeyPEM(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, version.Must(version.NewVersion("2.1.0")))
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					publicKey:       pubKeyP256,
					deletionAllowed: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "type", "ecdsa-p256"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version_type", "ecdsa-p256"),
				),
			},
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					mount:             mount,
					name:              keyName,
					keyType:           "ecdsa-p256",
					publicKey:         pubKeyP384,
					importVersionType: "ecdsa-p384",
					deletionAllowed:   true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "type", "ecdsa-p256"),
					resource.TestCheckResourceAttr(resourceAddress, "import_version_type", "ecdsa-p384"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version_type", "ecdsa-p384"),
				),
			},
		},
	})
}

// TestAccTransitImportedKey_rejectVaultCreatedKey verifies that importing a key
// that Vault generated itself (imported_key=false) into
// vault_transit_secret_backend_imported_key is rejected.
func TestAccTransitImportedKey_rejectVaultCreatedKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a mount and a Vault-generated key.
			{
				Config: fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transit"
}

resource "vault_transit_secret_backend_key" "native" {
  backend          = vault_mount.test.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}
`, mount, keyName),
			},
			// Step 2: Importing the Vault-created key must fail. Literal values are used
			// so the config doesn't depend on resources from step 1.
			{
				Config: fmt.Sprintf(`
resource "vault_transit_secret_backend_imported_key" "test" {
  mount = %q
  name  = %q
  type  = "aes256-gcm96"
}
`, mount, keyName),
				ResourceName:  resourceAddress,
				ImportState:   true,
				ImportStateId: fmt.Sprintf("%s/%s", mount, keyName),
				ExpectError:   regexp.MustCompile("Key was not imported into Vault"),
			},
		},
	})
}

// TestAccTransitImportedKey_terraformImportPublicKey validates adopting a key that was
// imported into Vault outside of Terraform with a public key:
//   - Step 1: terraform import (persisted), no key material in config
//   - Step 2: config without key material -> empty plan, key is only adopted
//   - Step 3: add a new public_key -> in-place update, version 2 is imported
//   - Step 4: add the private key for version 1 -> attached to version 1, latest_version stays 2
func TestAccTransitImportedKey_terraformImportPublicKey(t *testing.T) {
	acctestutil.SkipTestAcc(t)
	acctestutil.TestAccPreCheck(t)

	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	wrappingKey := testAccTransitImportedKeyWrappingKey(t, mount)
	pubKey1, privKey1 := generateTestECDSAKeyPair(t)
	pubKey2 := generateTestECDSAPublicKeyPEM(t)
	privKey1Ciphertext := createTransitBYOKCiphertext(t, wrappingKey, privKey1)

	importKeyVaultSetup(t, mount, keyName, map[string]any{
		"type":       "ecdsa-p256",
		"public_key": pubKey1,
	})

	adoptConfig := importedKeyConfig(transitImportedKeyFields{
		directMount:     true,
		deletionAllowed: true,
		mount:           mount,
		name:            keyName,
		keyType:         "ecdsa-p256",
	})

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config:             adoptConfig,
				ResourceName:       resourceAddress,
				ImportState:        true,
				ImportStateId:      fmt.Sprintf("%s/%s", mount, keyName),
				ImportStatePersist: true,
			},
			{
				Config: adoptConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
			},
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:     true,
					deletionAllowed: true,
					mount:           mount,
					name:            keyName,
					keyType:         "ecdsa-p256",
					publicKey:       pubKey2,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
			},
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "ecdsa-p256",
					publicKey:           pubKey2,
					ciphertext:          privKey1Ciphertext,
					ciphertextWOVersion: 1,
					version:             1,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
			},
		},
	})
}

// TestAccTransitImportedKey_terraformImportWrappedKey validates adopting a key that was
// imported into Vault outside of Terraform with a wrapped ciphertext:
//   - Step 1: terraform import (persisted), no key material in config
//   - Step 2: config without key material -> empty plan, key is only adopted
//   - Step 3: add ciphertext_wo and ciphertext_wo_version -> in-place update, version 2
//   - Step 4: add hash_function = SHA512 with a SHA512-wrapped ciphertext -> version 3
func TestAccTransitImportedKey_terraformImportWrappedKey(t *testing.T) {
	acctestutil.SkipTestAcc(t)
	acctestutil.TestAccPreCheck(t)

	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_imported_key.test"

	wrappingKey := testAccTransitImportedKeyWrappingKey(t, mount)

	rawKeys := make([][]byte, 3)
	for i := range rawKeys {
		rawKeys[i] = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, rawKeys[i]); err != nil {
			t.Fatalf("failed to generate random AES key: %v", err)
		}
	}
	ciphertext1 := createTransitBYOKCiphertext(t, wrappingKey, rawKeys[0])
	ciphertext2 := createTransitBYOKCiphertext(t, wrappingKey, rawKeys[1])
	ciphertext3 := createTransitBYOKCiphertextWithHash(t, wrappingKey, rawKeys[2], "SHA512")

	importKeyVaultSetup(t, mount, keyName, map[string]any{
		"type":       "aes256-gcm96",
		"ciphertext": ciphertext1,
	})

	adoptConfig := importedKeyConfig(transitImportedKeyFields{
		directMount:     true,
		deletionAllowed: true,
		mount:           mount,
		name:            keyName,
		keyType:         "aes256-gcm96",
	})

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config:             adoptConfig,
				ResourceName:       resourceAddress,
				ImportState:        true,
				ImportStateId:      fmt.Sprintf("%s/%s", mount, keyName),
				ImportStatePersist: true,
			},
			{
				Config: adoptConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
			},
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "aes256-gcm96",
					ciphertext:          ciphertext2,
					ciphertextWOVersion: 1,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
			},
			{
				Config: importedKeyConfig(transitImportedKeyFields{
					directMount:         true,
					deletionAllowed:     true,
					mount:               mount,
					name:                keyName,
					keyType:             "aes256-gcm96",
					ciphertext:          ciphertext3,
					ciphertextWOVersion: 2,
					hashFunction:        "SHA512",
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.TestCheckResourceAttr(resourceAddress, "latest_version", "3"),
			},
		},
	})
}

// importKeyVaultSetup imports a key into an existing transit mount through the Vault API.
// This is how a user's pre-existing key would have been imported before terraform supported BYOK
// so we can test the new resource handles this workflow gracefully.
// deletion_allowed is enabled so the key can be destroyed at the end of the test.
func importKeyVaultSetup(t *testing.T, mount, name string, importBody map[string]any) {
	t.Helper()

	cli := acctestutil.TestProvider.Meta().(*provider.ProviderMeta).MustGetClient()
	if _, err := cli.Logical().Write(fmt.Sprintf("%s/keys/%s/import", mount, name), importBody); err != nil {
		t.Fatalf("failed to import key outside Terraform: %v", err)
	}
	if _, err := cli.Logical().Write(fmt.Sprintf("%s/keys/%s/config", mount, name), map[string]any{"deletion_allowed": true}); err != nil {
		t.Fatalf("failed to enable deletion_allowed: %v", err)
	}
}

// importedKeyConfig renders the resource config. By default it also declares vault_mount.test;
// set directMount to use f.mount as a literal path instead.
func importedKeyConfig(f transitImportedKeyFields) string {
	var optionalArgs string
	if f.publicKey != "" {
		optionalArgs += fmt.Sprintf("  public_key = %q\n", f.publicKey)
	}
	if f.ciphertext != "" {
		optionalArgs += fmt.Sprintf("  ciphertext_wo = %q\n  ciphertext_wo_version = %d\n", f.ciphertext, f.ciphertextWOVersion)
	}
	if f.hashFunction != "" {
		optionalArgs += fmt.Sprintf("  hash_function = %q\n", f.hashFunction)
	}
	if f.version > 0 {
		optionalArgs += fmt.Sprintf("  version = %d\n", f.version)
	}
	if f.importVersionType != "" {
		optionalArgs += fmt.Sprintf("  import_version_type = %q\n", f.importVersionType)
	}
	if f.allowRotation {
		optionalArgs += fmt.Sprintf("  allow_rotation = %t\n", f.allowRotation)
	}
	if f.deletionAllowed {
		optionalArgs += fmt.Sprintf("  deletion_allowed = %t\n", f.deletionAllowed)
	}
	if f.exportable {
		optionalArgs += fmt.Sprintf("  exportable = %t\n", f.exportable)
	}
	if f.allowPlaintextBackup {
		optionalArgs += fmt.Sprintf("  allow_plaintext_backup = %t\n", f.allowPlaintextBackup)
	}
	if f.autoRotatePeriod != nil {
		optionalArgs += fmt.Sprintf("  auto_rotate_period = %d\n", *f.autoRotatePeriod)
	}
	if f.minDecryptionVersion > 0 {
		optionalArgs += fmt.Sprintf("  min_decryption_version = %d\n", f.minDecryptionVersion)
	}
	if f.minEncryptionVersion > 0 {
		optionalArgs += fmt.Sprintf("  min_encryption_version = %d\n", f.minEncryptionVersion)
	}

	mountBlock := ""
	mountRef := fmt.Sprintf("%q", f.mount)
	if !f.directMount {
		mountBlock = fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transit"
}
`, f.mount)
		mountRef = "vault_mount.test.path"
	}

	return fmt.Sprintf(`%s
resource "vault_transit_secret_backend_imported_key" "test" {
  mount = %s
  name  = %q
  type  = %q
%s}
`, mountBlock, mountRef, f.name, f.keyType, optionalArgs)
}

func testAccTransitImportedKeyStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s/%s", rs.Primary.Attributes["mount"], rs.Primary.Attributes["name"]), nil
	}
}
