// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"

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

type transitKeyImportVersionFields struct {
	mount         string
	keyName       string
	keyType       string
	basePubKey    string
	versionPubKey string
}

// TestAccTransitKeyImportVersion_publicKey validates importing subsequent public key versions:
//   - Step 1: Create base key with public key
//   - Step 2: Import key version 2 with public_key
//   - Step 3: In-place update to import key version 3 with new public_key
//   - Step 4: Import state verification
func TestAccTransitKeyImportVersion_publicKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_key_import_version.test"

	pubKey1 := generateTestECDSAPublicKeyPEM(t)
	pubKey2 := generateTestECDSAPublicKeyPEM(t)
	pubKey3 := generateTestECDSAPublicKeyPEM(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create base imported key
			{
				Config: testAccTransitKeyImportVersionConfig(transitKeyImportVersionFields{
					mount:      mount,
					keyName:    keyName,
					keyType:    "ecdsa-p256",
					basePubKey: pubKey1,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key_import.base", "latest_version", "1"),
				),
			},
			// Step 2: Import key version 2
			{
				Config: testAccTransitKeyImportVersionConfig(transitKeyImportVersionFields{
					mount:         mount,
					keyName:       keyName,
					keyType:       "ecdsa-p256",
					basePubKey:    pubKey1,
					versionPubKey: pubKey2,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "key_name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "version", "2"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: In-place update to import key version 3
			{
				Config: testAccTransitKeyImportVersionConfig(transitKeyImportVersionFields{
					mount:         mount,
					keyName:       keyName,
					keyType:       "ecdsa-p256",
					basePubKey:    pubKey1,
					versionPubKey: pubKey3,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "key_name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "version", "3"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 4: Import state verification
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransitKeyImportVersionStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertextWO,
					consts.FieldCiphertextWOVersion,
					consts.FieldPublicKey,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

func testAccTransitKeyImportVersionConfig(f transitKeyImportVersionFields) string {
	var versionResource string
	if f.versionPubKey != "" {
		versionResource = fmt.Sprintf(`
resource "vault_transit_secret_backend_key_import_version" "test" {
	 mount      = vault_transit_secret_backend_key_import.base.mount
	 key_name   = vault_transit_secret_backend_key_import.base.name
	 public_key = %q
}
`, f.versionPubKey)
	}

	return fmt.Sprintf(`
resource "vault_mount" "test" {
	 path = %q
	 type = "transit"
}

resource "vault_transit_secret_backend_key_import" "base" {
	 mount            = vault_mount.test.path
	 name             = %q
	 type             = %q
	 public_key       = %q
	 deletion_allowed = true
}
%s`, f.mount, f.keyName, f.keyType, f.basePubKey, versionResource)
}

func testAccTransitKeyImportVersionStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s/%s/%s", rs.Primary.Attributes["mount"], rs.Primary.Attributes["key_name"], rs.Primary.Attributes["version"]), nil
	}
}

type transitKeyImportVersionWrappedFields struct {
	mount               string
	keyName             string
	keyType             string
	baseCiphertext      string
	versionCiphertextWO string
	versionWOVersion    int64
	versionHashFunction string
}

// TestAccTransitKeyImportVersion_wrappedKey validates importing and updating subsequent wrapped key versions:
//   - Step 1: Create base key with wrapped ciphertext (v1)
//   - Step 2: Import key version 2 with ciphertext_wo + hash_function = "SHA256"
//   - Step 3: In-place update to import key version 3 with new ciphertext_wo + incremented ciphertext_wo_version + hash_function = "SHA384"
//   - Step 4: Import state verification
func TestAccTransitKeyImportVersion_wrappedKey(t *testing.T) {
	acctestutil.TestAccPreCheck(t)

	mount := acctest.RandomWithPrefix("transit-mount")
	keyName := acctest.RandomWithPrefix("transit-key")
	resourceAddress := "vault_transit_secret_backend_key_import_version.test"

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
	rawAESKey3 := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawAESKey3); err != nil {
		t.Fatalf("failed to generate random AES key 3: %v", err)
	}
	ciphertext1 := createTransitBYOKCiphertext(t, pubKey, rawAESKey1)
	ciphertext2 := createTransitBYOKCiphertextWithHash(t, pubKey, rawAESKey2, "SHA256")
	ciphertext3 := createTransitBYOKCiphertextWithHash(t, pubKey, rawAESKey3, "SHA384")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			// Step 1: Create base imported key with wrapped ciphertext
			{
				Config: testAccTransitKeyImportVersionWrappedConfig(transitKeyImportVersionWrappedFields{
					mount:          mount,
					keyName:        keyName,
					keyType:        "aes256-gcm96",
					baseCiphertext: ciphertext1,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key_import.base", "latest_version", "1"),
				),
			},
			// Step 2: Import key version 2 with ciphertext_wo + ciphertext_wo_version + hash_function = "SHA256"
			{
				Config: testAccTransitKeyImportVersionWrappedConfig(transitKeyImportVersionWrappedFields{
					mount:               mount,
					keyName:             keyName,
					keyType:             "aes256-gcm96",
					baseCiphertext:      ciphertext1,
					versionCiphertextWO: ciphertext2,
					versionWOVersion:    1,
					versionHashFunction: "SHA256",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "key_name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "hash_function", "SHA256"),
					resource.TestCheckNoResourceAttr(resourceAddress, consts.FieldCiphertextWO),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: In-place update to import key version 3 with new ciphertext_wo + ciphertext_wo_version = 2 + hash_function = "SHA384"
			{
				Config: testAccTransitKeyImportVersionWrappedConfig(transitKeyImportVersionWrappedFields{
					mount:               mount,
					keyName:             keyName,
					keyType:             "aes256-gcm96",
					baseCiphertext:      ciphertext1,
					versionCiphertextWO: ciphertext3,
					versionWOVersion:    2,
					versionHashFunction: "SHA384",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "key_name", keyName),
					resource.TestCheckResourceAttr(resourceAddress, "version", "3"),
					resource.TestCheckResourceAttr(resourceAddress, "hash_function", "SHA384"),
					resource.TestCheckNoResourceAttr(resourceAddress, consts.FieldCiphertextWO),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 4: Import state verification
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransitKeyImportVersionStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertextWO,
					consts.FieldCiphertextWOVersion,
					consts.FieldPublicKey,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

func testAccTransitKeyImportVersionWrappedConfig(f transitKeyImportVersionWrappedFields) string {
	var versionResource string
	if f.versionCiphertextWO != "" {
		versionResource = fmt.Sprintf(`
resource "vault_transit_secret_backend_key_import_version" "test" {
	 mount                 = vault_transit_secret_backend_key_import.base.mount
	 key_name              = vault_transit_secret_backend_key_import.base.name
	 ciphertext_wo         = %q
	 ciphertext_wo_version = %d
	 hash_function         = %q
}
`, f.versionCiphertextWO, f.versionWOVersion, f.versionHashFunction)
	}

	return fmt.Sprintf(`
resource "vault_transit_secret_backend_key_import" "base" {
	 mount            = %q
	 name             = %q
	 type             = %q
	 ciphertext       = %q
	 deletion_allowed = true
}
%s`, f.mount, f.keyName, f.keyType, f.baseCiphertext, versionResource)
}
