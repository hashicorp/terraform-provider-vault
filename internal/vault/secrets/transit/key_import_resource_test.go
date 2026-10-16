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

type transitKeyImportFields struct {
	mount                string
	name                 string
	keyType              string
	publicKey            string
	ciphertext           string
	hashFunction         string
	allowRotation        bool
	exportable           bool
	allowPlaintextBackup bool
	autoRotatePeriod     int64
	minDecryptionVersion int64
	minEncryptionVersion int64
	deletionAllowed      bool
}

// TestAccTransitKeyImport_publicKey validates the lifecycle of importing a public key:
//   - Step 1: Create with required fields only (deletion_allowed and allow_rotation default to false)
//   - Step 2: In-place update of tunable configuration parameters (/config), enabling deletion_allowed
//   - Step 3: Change allow_rotation to true -> forces resource replacement (destroy + recreate)
//   - Step 4: Import state verification
func TestAccTransitKeyImport_publicKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_key_import.test"

	pubKey := generateTestECDSAPublicKeyPEM(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with required fields only (testing Vault defaults).
			{
				Config: testAccTransitKeyImportConfig(transitKeyImportFields{
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
					resource.TestCheckResourceAttr(resourceAddress, "hash_function", "SHA256"),
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
				Config: testAccTransitKeyImportConfig(transitKeyImportFields{
					mount:                mount,
					name:                 keyName,
					keyType:              "ecdsa-p256",
					publicKey:            pubKey,
					autoRotatePeriod:     3600,
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
				Config: testAccTransitKeyImportConfig(transitKeyImportFields{
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
				ImportStateIdFunc:                    testAccTransitKeyImportStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				// These are all values that are not returned by vault.
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertext,
					consts.FieldContext,
					consts.FieldPublicKey,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

// TestAccTransitKeyImport_wrappedKey validates importing wrapped symmetric key material:
//   - Step 1: Create with wrapped AES-256 ciphertext
//   - Step 2: Modify ciphertext -> verify resource replacement (destroy + recreate)
//   - Step 3: Import state verification
func TestAccTransitKeyImport_wrappedKey(t *testing.T) {
	acctestutil.TestAccPreCheck(t)

	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_key_import.test"

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
			// Step 1: Create with initial wrapped ciphertext
			{
				Config: testAccTransitKeyImportConfigDirectMount(transitKeyImportFields{
					mount:      mount,
					name:       keyName,
					keyType:    "aes256-gcm96",
					ciphertext: ciphertext1,
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
			// Step 2: Modify ciphertext -> verify resource replacement (destroy + recreate)
			{
				Config: testAccTransitKeyImportConfigDirectMount(transitKeyImportFields{
					mount:      mount,
					name:       keyName,
					keyType:    "aes256-gcm96",
					ciphertext: ciphertext2,
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
					resource.TestCheckResourceAttr(resourceAddress, "type", "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
				),
			},
			// Step 3: Import state verification
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransitKeyImportStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertext,
					consts.FieldContext,
					consts.FieldPublicKey,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

// TestAccTransitKeyImport_optionalFields validates setting optional fields at import
func TestAccTransitKeyImport_optionalFields(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_key_import.test"

	pubKey := generateTestRSAPublicKeyPEM(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTransitKeyImportConfig(transitKeyImportFields{
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
				Config: testAccTransitKeyImportConfig(transitKeyImportFields{
					mount:                mount,
					name:                 keyName,
					keyType:              "rsa-2048",
					publicKey:            pubKey,
					exportable:           true,
					allowPlaintextBackup: true,
					allowRotation:        true,
					hashFunction:         "SHA384",
					autoRotatePeriod:     3600,
					minDecryptionVersion: 1,
					minEncryptionVersion: 1,
					deletionAllowed:      true,
				}),
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
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Import state verification
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransitKeyImportStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertext,
					consts.FieldContext,
					consts.FieldPublicKey,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

// TestAccTransitKeyImport_versionImportedDuringUpdate verifies that computed
// attributes Vault can change outside this resource (latest_version, keys,
// min_available_version) are not planned with UseStateForUnknown. Otherwise,
// importing a key version in the same apply makes Vault return a different
// value than the plan and Terraform fails with "inconsistent result after apply".
//
// The version resource doesn't reference the key, so the key uses depends_on to
// make the version import run first. That makes the ordering deterministic.
//
//   - Step 1: Create the key at version 1.
//   - Step 2: Update the key and import version 2 in the same apply.
//   - Step 3: Change min_decryption_version alone (the key's own Update).
func TestAccTransitKeyImport_versionImportedDuringUpdate(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_key_import.test"

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
				Config: testAccTransitKeyImportVersionDuringUpdateConfig(mount, keyName, pubKey1, "", false, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "exportable", "false"),
				),
			},
			// Step 2: Update the key and import version 2 in the same apply.
			{
				Config: testAccTransitKeyImportVersionDuringUpdateConfig(mount, keyName, pubKey1, pubKey2, true, 0),
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
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key_import_version.v2", "version", "2"),
					// Values that changed due to the version import, not the key's Update.
					resource.TestCheckResourceAttr(resourceAddress, "latest_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "keys.%", "2"),
					// Unchanged by a same-type version import; asserted to document that.
					resource.TestCheckResourceAttr(resourceAddress, "min_available_version", "0"),
				),
			},
			// Step 3: Change min_decryption_version alone (the key's own Update).
			{
				Config: testAccTransitKeyImportVersionDuringUpdateConfig(mount, keyName, pubKey1, pubKey2, true, 2),
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
				),
			},
		},
	})
}

// TestAccTransitKeyImport_rejectVaultCreatedKey verifies that importing a key
// that Vault generated itself (imported_key=false) into
// vault_transit_secret_backend_key_import is rejected.
func TestAccTransitKeyImport_rejectVaultCreatedKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_key_import.test"

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
resource "vault_transit_secret_backend_key_import" "test" {
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

// testAccTransitKeyImportVersionDuringUpdateConfig builds a config where the
// version resource uses literal mount and key_name values, so it has no implicit
// dependency on the key. The key depends_on the version resource to force the
// version import to run before the key's Update. minDecryptionVersion is only
// set when > 0.
func testAccTransitKeyImportVersionDuringUpdateConfig(mount, keyName, basePubKey, versionPubKey string, exportable bool, minDecryptionVersion int) string {
	var dependsOn, versionResource, minDecryption string
	if versionPubKey != "" {
		dependsOn = "  depends_on = [vault_transit_secret_backend_key_import_version.v2]\n"
		versionResource = fmt.Sprintf(`
resource "vault_transit_secret_backend_key_import_version" "v2" {
  mount      = %q
  key_name   = %q
  public_key = %q

  # The mount is a literal, so order after the mount explicitly. There is
  # deliberately no reference to the key resource.
  depends_on = [vault_mount.test]
}
`, mount, keyName, versionPubKey)
	}
	if minDecryptionVersion > 0 {
		minDecryption = fmt.Sprintf("  min_decryption_version = %d\n", minDecryptionVersion)
	}

	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transit"
}

resource "vault_transit_secret_backend_key_import" "test" {
  mount            = vault_mount.test.path
  name             = %q
  type             = "ecdsa-p256"
  public_key       = %q
  deletion_allowed = true
  exportable       = %t
%s%s}
%s`, mount, keyName, basePubKey, exportable, minDecryption, dependsOn, versionResource)
}

func testAccTransitKeyImportConfig(f transitKeyImportFields) string {
	var optionalArgs string
	if f.publicKey != "" {
		optionalArgs += fmt.Sprintf("  public_key = %q\n", f.publicKey)
	}
	if f.ciphertext != "" {
		optionalArgs += fmt.Sprintf("  ciphertext = %q\n", f.ciphertext)
	}
	if f.hashFunction != "" {
		optionalArgs += fmt.Sprintf("  hash_function = %q\n", f.hashFunction)
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
	if f.autoRotatePeriod > 0 {
		optionalArgs += fmt.Sprintf("  auto_rotate_period = %d\n", f.autoRotatePeriod)
	}
	if f.minDecryptionVersion > 0 {
		optionalArgs += fmt.Sprintf("  min_decryption_version = %d\n", f.minDecryptionVersion)
	}
	if f.minEncryptionVersion > 0 {
		optionalArgs += fmt.Sprintf("  min_encryption_version = %d\n", f.minEncryptionVersion)
	}

	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transit"
}

resource "vault_transit_secret_backend_key_import" "test" {
  mount = vault_mount.test.path
  name  = %q
  type  = %q
%s}
`, f.mount, f.name, f.keyType, optionalArgs)
}

func testAccTransitKeyImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s/%s", rs.Primary.Attributes["mount"], rs.Primary.Attributes["name"]), nil
	}
}

func testAccTransitKeyImportConfigDirectMount(f transitKeyImportFields) string {
	var optionalArgs string
	if f.publicKey != "" {
		optionalArgs += fmt.Sprintf("  public_key = %q\n", f.publicKey)
	}
	if f.ciphertext != "" {
		optionalArgs += fmt.Sprintf("  ciphertext = %q\n", f.ciphertext)
	}
	if f.hashFunction != "" {
		optionalArgs += fmt.Sprintf("  hash_function = %q\n", f.hashFunction)
	}
	if f.allowRotation {
		optionalArgs += fmt.Sprintf("  allow_rotation = %t\n", f.allowRotation)
	}
	if f.exportable {
		optionalArgs += fmt.Sprintf("  exportable = %t\n", f.exportable)
	}
	if f.allowPlaintextBackup {
		optionalArgs += fmt.Sprintf("  allow_plaintext_backup = %t\n", f.allowPlaintextBackup)
	}
	if f.autoRotatePeriod > 0 {
		optionalArgs += fmt.Sprintf("  auto_rotate_period = %d\n", f.autoRotatePeriod)
	}
	if f.minDecryptionVersion > 0 {
		optionalArgs += fmt.Sprintf("  min_decryption_version = %d\n", f.minDecryptionVersion)
	}
	if f.minEncryptionVersion > 0 {
		optionalArgs += fmt.Sprintf("  min_encryption_version = %d\n", f.minEncryptionVersion)
	}

	// deletion_allowed=true is hardcoded here because this template is used by
	// tests that trigger resource replacement or final destroy. Without it Vault
	// rejects the DELETE and the test fails with a 400.
	return fmt.Sprintf(`
resource "vault_transit_secret_backend_key_import" "test" {
	 mount            = %q
	 name             = %q
	 type             = %q
	 deletion_allowed = true
%s}
`, f.mount, f.name, f.keyType, optionalArgs)
}
