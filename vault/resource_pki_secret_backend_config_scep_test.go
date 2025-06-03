// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPKISecretBackendConfigScep_Empty(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_scep"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_scep.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion120)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigScepDisabled(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".#", "4"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".0", "aes128-cbc"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".1", "aes128-gcm"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".2", "aes256-cbc"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".3", "aes256-gcm"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".#", "3"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".0", "sha-256"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".1", "sha-384"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".2", "sha-512"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldRestrictCAChainToIssuer, "false"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert"),
					resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.scep"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldExternalValidation+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldExternalValidation+".0.%", "1"),
					resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldExternalValidation+".0.intune"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldLastUpdated),

					// Validate we read back the data back as we did upon creation
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".#", "4"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".0", "aes128-cbc"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".1", "aes128-gcm"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".2", "aes256-cbc"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".3", "aes256-gcm"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldRestrictCAChainToIssuer, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.cert"),
					resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.scep"),
					resource.TestCheckResourceAttr(dataName, consts.FieldExternalValidation+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldExternalValidation+".0.%", "1"),
					resource.TestCheckNoResourceAttr(dataName, consts.FieldExternalValidation+".0.intune"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, false, nil),
		},
	})
}

func testAccPKISecretBackendConfigScepDisabled(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_config_scep" "test" {
  backend = vault_mount.test.path
}

data "vault_pki_secret_backend_config_scep" "test" {
  backend = vault_pki_secret_backend_config_scep.test.backend
}
`, path)
}

func TestAccPKISecretBackendConfigScep_AllFields(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_scep"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_scep.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion120)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigScepComplete(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, "role:default-path-policy-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".#", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".0", "des-cbc"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".1", "3des-cbc"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".0", "sha-1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldRestrictCAChainToIssuer, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.accessor", "test"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.cert_role", "cert-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.scep.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.scep.accessor", "auth-scep-accessor"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.scep.scep_role", "scep-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldExternalValidation+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldExternalValidation+".0.%", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldExternalValidation+".0.intune.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldExternalValidation+".0.intune.client_id", "the client ID"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldExternalValidation+".0.intune.tenant_id", "the tenant ID"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldLastUpdated),

					// Validate that the data property can read back everything filled in
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, "role:default-path-policy-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".#", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".0", "des-cbc"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".1", "3des-cbc"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedDigestAlgorithms+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedDigestAlgorithms+".0", "sha-1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldRestrictCAChainToIssuer, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.accessor", "test"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.cert_role", "cert-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.scep.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.scep.accessor", "auth-scep-accessor"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.scep.scep_role", "scep-role"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, false, nil),
		},
	})
}

func testAccPKISecretBackendConfigScepComplete(pkiPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}
resource "vault_pki_secret_backend_config_scep" "test" {
  backend = vault_mount.test.path
  enabled = true
  default_path_policy = "role:default-path-policy-role"
  allowed_encryption_algorithms = ["des-cbc", "3des-cbc"]
  allowed_digest_algorithms = ["sha-1"]
  restrict_ca_chain_to_issuer = true
  authenticators { 
	cert = { "accessor" = "test", "cert_role" = "cert-role" }
    scep = { "accessor" = "auth-scep-accessor", "scep_role" = "scep-role"}
  }	
  external_validation {
    intune = { 
      client_id = "the client ID"
      tenant_id = "the tenant ID"
      client_secret = "the client secret"
    }
  }
}

data "vault_pki_secret_backend_config_scep" "test" {
  backend = vault_pki_secret_backend_config_scep.test.backend
}
`, pkiPath)
}
