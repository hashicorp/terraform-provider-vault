// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-provider-vault/internal/helpers"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			helpers.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
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

func TestAccPKISecretBackendConfigEst_Blank(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_est"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_est.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			helpers.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigAllKeysBlank(backend),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			helpers.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
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
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
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
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
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

/*
TestAccPKISecretBackendConfigEst_ChangeFields ensures that all fields can both be set and then unset.
It does this by:
Step 1: Configure with a Blank Configuration
import
Step 3: Configure with a Complete Configuration
import
Step 5: Configure with a Complete-Blank Configuration (that is, all keys exist, but fields are returned to default)
import
Step 7: Configure with a Blank Configuration (again)
import
*/
func TestAccPKISecretBackendConfigEst_ChangeFields(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_est"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_est.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			helpers.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{ // Step 1: Configure with a Blank Configuration:
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
			{ // Step 3: Configure with a Complete Configuration:
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
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
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
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass.%", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass.accessor", "test2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnableSentinelParsing, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuditFields+".#", "20"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, false, nil),
			//{
			//	Config:   testAccPKISecretBackendConfigAllKeysBlank(backend),
			//	PlanOnly: true,
			//	ConfigPlanChecks: resource.ConfigPlanChecks{
			//		PostApplyPreRefresh: []plancheck.PlanCheck{
			//			DebugPlan(),
			//		},
			//	},
			//},
			{ // Step 5: Configure with an Complete but Empty Configuration
				Config: testAccPKISecretBackendConfigAllKeysBlank(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultMount, "false"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldLabelToPathPolicy+".%", "0"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "2"),
					// Previous Empty Map Checks (that will fail):
					// resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert"),
					// resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass"),
					// These two checks do differ from the empty-map check, but is equivalent on the Vault-Side
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.%", "0"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.scep.%", "0"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldLastUpdated),

					// Validate we read back the data back as we did upon creation
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultMount, "false"),
					// See VAULT-38845 for work to fix this:
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldLabelToPathPolicy+".%", "0"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "2"),
					// Previous Empty Map Checks (that will fail):
					// resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.cert"),
					// resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass"),
					// These two checks do differ from the empty-map check, but is equivalent on the Vault-Side
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.%", "0"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.scep.%", "0"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, true, nil),
			{ // Step 7: Configure with a Blank Configuration Again
				Config: testAccPKISecretBackendConfigEstDisabled(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultMount, "false"),
					// See VAULT-38845 for work to fix this:
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldLabelToPathPolicy+".%", "0"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "2"),
					// Previous Empty Map Checks (that will fail):
					// resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert"),
					// resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.userpass"),
					// These two checks do differ from the empty-map check, but is equivalent on the Vault-Side
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.%", "0"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.scep.%", "0"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldLastUpdated),

					// Validate we read back the data back as we did upon creation
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultMount, "false"),
					// See VAULT-38845 for work to fix this:
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldLabelToPathPolicy+".%", "0"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "2"),
					// Previous Empty Map Checks (that will fail):
					// resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.cert"),
					// resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.userpass"),
					// These two checks do differ from the empty-map check, but is equivalent on the Vault-Side
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.%", "0"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.scep.%", "0"),
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
	cert = { "accessor" = "test", "cert_role" = "a-role" }
	userpass = { "accessor" = "test2" } 
  }	
  enable_sentinel_parsing = true
  audit_fields = ["csr", "common_name", "alt_names", "ip_sans", "uri_sans", "other_sans",
                  "signature_bits", "exclude_cn_from_sans", "ou", "organization", "country", 
                  "locality", "province", "street_address", "postal_code", "serial_number",
                  "use_pss", "key_type", "key_bits", "add_basic_constraints"]
}

data "vault_pki_secret_backend_config_est" "test" {
  backend = vault_pki_secret_backend_config_est.test.backend	
}
`, pkiPath)
}

func testAccPKISecretBackendConfigAllKeysBlank(pkiPath string) string {
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
  enabled = false
  default_mount = false
  default_path_policy = ""
  label_to_path_policy = {
  }
  authenticators {
  }
  enable_sentinel_parsing = false
  audit_fields = ["common_name", "alt_names", "ip_sans", "uri_sans"]
}

data "vault_pki_secret_backend_config_est" "test" {
  backend = vault_pki_secret_backend_config_est.test.backend    
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
  backend = vault_pki_secret_backend_config_est.test.backend	
}
`, path)
}

// Taken from https://discuss.hashicorp.com/t/framework-migration-test-produces-non-empty-plan/54523/12
// to cover oddities about null vs. empty errors
var _ plancheck.PlanCheck = debugPlan{}

type debugPlan struct{}

func (e debugPlan) CheckPlan(ctx context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	rd, err := json.Marshal(req.Plan)
	if err != nil {
		fmt.Println("error marshalling machine-readable plan output:", err)
	}
	fmt.Printf("req.Plan - %s\n", string(rd))
}

func DebugPlan() plancheck.PlanCheck {
	return debugPlan{}
}
