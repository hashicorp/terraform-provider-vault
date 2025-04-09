// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPKISecretBackendConfigScep_Empty(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_scep"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_scep.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
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

					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert"),
					resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
					func(s *terraform.State) error {
						_ = s
						return nil
					},

					// Validate we read back the data back as we did upon creation
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.cert"),
					resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, false, nil),
		},
	})

}

func TestAccPKISecretBackendConfigScep_AllFields(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_scep"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_scep.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
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
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, "role:scep-role"),

					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".#", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".0", "des-cbc"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedEncryptionAlgorithms+".1", "3des-cbc"),

					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".#", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".0", "sha-1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAllowedDigestAlgorithms+".1", "sha-256"),

					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.accessor", "the-cert-accessor"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass.accessor", "the-userpass-accessor"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass.username", "the-scep-user"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),

					// Validate that the data property can read back everything filled in
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".#", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".0", "des-cbc"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedEncryptionAlgorithms+".1", "3des-cbc"),

					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedDigestAlgorithms+".#", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedDigestAlgorithms+".0", "sha-1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAllowedDigestAlgorithms+".1", "sha-256"),

					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.accessor", "the-cert-accessor"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass.accessor", "the-userpass-accessor"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass.username", "the-scep-user"),
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

resource "vault_pki_secret_backend_role" "scep_role" {
  backend = vault_mount.test.path
  name = "scep-role"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_config_scep" "test" {
  backend = vault_mount.test.path
  enabled = true
  default_path_policy = format("role:%%s", vault_pki_secret_backend_role.scep_role.name)
  allowed_encryption_algorithms = ["des-cbc", "3des-cbc"]
  allowed_digest_algorithms = ["sha-1", "sha-256"]
  authenticators { 
	cert = { "accessor" = "the-cert-accessor", "cert_role" = "a-role" }
	userpass = { "accessor" = "the-userpass-accessor", "username" = "the-scep-user" } 
  }	
}

data "vault_pki_secret_backend_config_scep" "test" {
  backend = vault_pki_secret_backend_config_scep.test.backend	
}
`, pkiPath)
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
