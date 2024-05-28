// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPKISecretBackendConfigEst_Empty(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_est"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_est.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigEstDisabled(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultMount, "false"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldLabelToPathPolicy+".%", "0"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert"),
					resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),

					// Validate we read back the data back as we did upon creation
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultMount, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldLabelToPathPolicy+".%", "0"),
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

func TestAccPKISecretBackendConfigEst_AllFields(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_est"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_est.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigEstComplete(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultMount, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, "role:est-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldLabelToPathPolicy+".%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldLabelToPathPolicy+".test-label", "sign-verbatim"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldLabelToPathPolicy+".test-label-2", "role:est-role-2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.accessor", "test"),
					// @TODO add these back in when Vault 1.16.3 is released (https://github.com/hashicorp/vault-enterprise/pull/5785)
					// resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass.%", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass.accessor", "test2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnableSentinelParsing, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuditFields+".#", "20"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),

					// Validate that the data property can read back everything filled in
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultMount, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, "role:est-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldLabelToPathPolicy+".%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldLabelToPathPolicy+".test-label", "sign-verbatim"),
					resource.TestCheckResourceAttr(dataName, consts.FieldLabelToPathPolicy+".test-label-2", "role:est-role-2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.accessor", "test"),
					// @TODO add these back in when Vault 1.16.3 is released (https://github.com/hashicorp/vault-enterprise/pull/5785)
					// resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass.%", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass.accessor", "test2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnableSentinelParsing, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuditFields+".#", "20"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, false, nil),
		},
	})
}

func testAccPKISecretBackendConfigEstComplete(pkiPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_role" "est_role" {
  backend = vault_mount.test.path
  name = "est-role"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_role" "est_role_2" {
  backend = vault_mount.test.path
  name = "est-role-2"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_config_est" "test" {
  backend = vault_mount.test.path
  enabled = true
  default_mount = true
  default_path_policy = format("role:%%s", vault_pki_secret_backend_role.est_role.name)
  label_to_path_policy = {
     "test-label": "sign-verbatim",
     "test-label-2": format("role:%%s", vault_pki_secret_backend_role.est_role_2.name)
  }
  authenticators { 
	# @TODO add these back in when Vault 1.16.3 is released (https://github.com/hashicorp/vault-enterprise/pull/5785)
	# cert = { "accessor" = "test", "cert_role" = "a-role" }
	cert = { "accessor" = "test", "cert_role" = "" }
	userpass = { "accessor" = "test2" } 
  }	
  enable_sentinel_parsing = true
  audit_fields = ["csr", "common_name", "alt_names", "ip_sans", "uri_sans", "other_sans",
                  "signature_bits", "exclude_cn_from_sans", "ou", "organization", "country", 
                  "locality", "province", "street_address", "postal_code", "serial_number",
                  "use_pss", "key_type", "key_bits", "add_basic_constraints"]
}

data "vault_pki_secret_backend_config_est" "test" {
  depends_on = [vault_pki_secret_backend_config_est.test]
  backend = vault_mount.test.path
}
`, pkiPath)
}

func testAccPKISecretBackendConfigEstDisabled(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_config_est" "test" {
  backend = vault_mount.test.path
}

data "vault_pki_secret_backend_config_est" "test" {
  depends_on = [vault_pki_secret_backend_config_est.test]
  backend = vault_mount.test.path
}
`, path)
}
