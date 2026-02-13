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
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func TestTransitSecretBackendKey_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resourceName := "vault_transit_secret_backend_key.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_basic(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAutoRotatePeriod, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergentEncryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDerived, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExportable, "false"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLatestVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDecryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDerivation, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsEncryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsSigning, "false"),
				),
			},
			{
				Config: testTransitSecretBackendKeyConfig_updated(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAutoRotatePeriod, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergentEncryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDerived, "false"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLatestVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDecryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDerivation, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsEncryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsSigning, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMinDecryptionVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMinEncryptionVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExportable, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowPlaintextBackup, "true"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldKeySize, consts.FieldManagedKeyID},
			},
			{
				Config:      testTransitSecretBackendKeyConfig_invalidUpdates(name, backend),
				ExpectError: regexp.MustCompile("cannot be disabled on a key that already has it enabled"),
			},
			{
				Config:  testTransitSecretBackendKeyConfig_updated(name, backend),
				Destroy: true,
			},
		},
	})
}

func TestTransitSecretBackendKey_rsa4096(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resourceName := "vault_transit_secret_backend_key.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_rsa4096(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergentEncryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDerived, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExportable, "false"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLatestVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "rsa-4096"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDecryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDerivation, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsEncryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsSigning, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAutoRotatePeriod, "0"),
				),
			},
			{
				Config: testTransitSecretBackendKeyConfig_rsa4096updated(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergentEncryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDerived, "false"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLatestVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "rsa-4096"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDecryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDerivation, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsEncryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsSigning, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMinDecryptionVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMinEncryptionVersion, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExportable, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowPlaintextBackup, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAutoRotatePeriod, "0"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldKeySize},
			},
		},
	})
}

func TestTransitSecretBackendKey_hmac(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resourceName := "vault_transit_secret_backend_key.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_hmac(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergentEncryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDerived, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExportable, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeySize, "32"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLatestVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "hmac"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDecryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDerivation, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsEncryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsSigning, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAutoRotatePeriod, "0"),
				),
			},
			{
				Config: testTransitSecretBackendKeyConfig_hmacupdated(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergentEncryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDerived, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeySize, "32"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLatestVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "hmac"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDecryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDerivation, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsEncryption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsSigning, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMinDecryptionVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMinEncryptionVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExportable, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowPlaintextBackup, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAutoRotatePeriod, "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testTransitSecretBackendKeyConfig_basic(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  deletion_allowed = true
  auto_rotate_period = 3600
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_rsa4096(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  deletion_allowed = true
  type = "rsa-4096"
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_hmac(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  deletion_allowed = true
  type = "hmac"
  key_size = 32
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_rsa4096updated(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  deletion_allowed = true
  type = "rsa-4096"
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_hmacupdated(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  deletion_allowed = true
  type = "hmac"
  key_size = 32
  min_decryption_version = 1
  min_encryption_version = 1
  exportable             = true
  allow_plaintext_backup = true
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_updated(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  min_decryption_version = 1
  min_encryption_version = 1
  deletion_allowed       = true
  auto_rotate_period     = 7200
  exportable             = true
  allow_plaintext_backup = true
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_invalidUpdates(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  min_decryption_version = 1
  min_encryption_version = 1
  deletion_allowed       = true
  exportable             = false
  allow_plaintext_backup = false
}
`, path, name)
}

func testTransitSecretBackendKeyCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transit_secret_backend_key" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("Key %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestTransitSecretBackendKey_context(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resourceName := "vault_transit_secret_backend_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_context(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDerived, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergentEncryption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldContext, "dGVzdGNvbnRleHQ="), // base64 encoded "testcontext"
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSupportsDerivation, "true"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLatestVersion, "1"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldKeySize, consts.FieldContext},
			},
		},
	})
}

func TestTransitSecretBackendKey_managedKeyName(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	managedKeyName := acctest.RandomWithPrefix("managed-key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
		},
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					// Skip test if not Enterprise Vault
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if !meta.IsEnterpriseSupported() {
						t.Skip("Managed keys are an enterprise-only feature")
					}
				},
				Config:      testTransitSecretBackendKeyConfig_managedKeyName(name, backend, managedKeyName),
				ExpectError: regexp.MustCompile("no managed key found with name"),
			},
		},
	})
}

func TestTransitSecretBackendKey_managedKeyId(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	// Example UUID for testing - in real scenarios this would be a real managed key UUID
	managedKeyId := "12345678-1234-5678-9012-123456789012"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
		},
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					// Skip test if not Enterprise Vault
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if !meta.IsEnterpriseSupported() {
						t.Skip("Managed keys are an enterprise-only feature")
					}
				},
				Config:      testTransitSecretBackendKeyConfig_managedKeyId(name, backend, managedKeyId),
				ExpectError: regexp.MustCompile("no managed key found with uuid"),
			},
		},
	})
}

func TestTransitSecretBackendKey_managedKey(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	managedKeyName := acctest.RandomWithPrefix("managed-key")
	var managedKeyId string

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
		},
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					// Skip test if not Enterprise Vault
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if !meta.IsEnterpriseSupported() {
						t.Skip("Managed keys are an enterprise-only feature")
					}

					// Create a managed key in Vault first
					client, err := provider.GetClient("", testProvider.Meta())
					if err != nil {
						t.Fatalf("failed to get client: %s", err)
					}

					data := map[string]interface{}{
						"access_key": "ASIAKBASDADA09090",
						"secret_key": "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz",
						"key_bits":   "2048",
						"key_type":   "RSA",
						"kms_key":    "12345678-1234-1234-1234-123456789012",
					}

					path := fmt.Sprintf("sys/managed-keys/awskms/%s", managedKeyName)
					resp, err := client.Logical().Write(path, data)
					if err != nil {
						t.Fatalf("failed to create Vault managed key %q, err=%s", path, err)
					}
					if resp != nil && resp.Data != nil && resp.Data["uuid"] != nil {
						managedKeyId = resp.Data["uuid"].(string)
					}
				},
				Config:      testTransitSecretBackendKeyConfig_managedKey(name, backend, managedKeyName, managedKeyId),
				ExpectError: regexp.MustCompile("UnrecognizedClientException|security token.*invalid|error fetching AWS KMS wrapping key information"),
			},
		},
	})
}

func testTransitSecretBackendKeyConfig_context(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  derived = true
  convergent_encryption = true
  context = "dGVzdGNvbnRleHQ="  # base64 encoded "testcontext"
  deletion_allowed = true
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_managedKeyName(name, path, managedKeyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  type = "managed_key"
  managed_key_name = "%s"
  deletion_allowed = true
}
`, path, name, managedKeyName)
}

func testTransitSecretBackendKeyConfig_managedKeyId(name, path, managedKeyId string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  type = "managed_key"
  managed_key_id = "%s"
  deletion_allowed = true
}
`, path, name, managedKeyId)
}

func testTransitSecretBackendKeyConfig_managedKey(name, path, managedKeyName, managedKeyId string) string {
	managedKeyIdConfig := ""
	if managedKeyId != "" {
		managedKeyIdConfig = fmt.Sprintf("\n  managed_key_id = \"%s\"", managedKeyId)
	}
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
  
  # Enable managed keys for this mount
  allowed_managed_keys = ["%s"]
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  type = "managed_key"
  managed_key_name = "%s"%s
  deletion_allowed = true
}
`, path, managedKeyName, name, managedKeyName, managedKeyIdConfig)
}
