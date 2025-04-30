// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPKISecretBackendConfigCMPV2_Empty(t *testing.T) {
	var p *schema.Provider
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_cmpv2"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_cmpv2.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigCMPV2Disabled(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckNoResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),

					// Validate we read back the data back as we did upon creation
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldLabelToPathPolicy+".%", "0"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckNoResourceAttr(dataName, consts.FieldAuthenticators+".0.cert"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, false, nil),
		},
	})

}

func TestAccPKISecretBackendConfigCMPV2_AllFields_Pre1185(t *testing.T) {
	var p *schema.Provider
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_cmpv2"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_cmpv2.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigCMPV2Complete(backend, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, "role:cmpv2-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.accessor", "test"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnableSentinelParsing, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuditFields+".#", "20"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldLastUpdated),

					// Validate that the data property can read back everything filled in
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, "role:cmpv2-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.accessor", "test"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnableSentinelParsing, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuditFields+".#", "20"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, false, nil),
		},
	})
}

func TestAccPKISecretBackendConfigCMPV2_AllFields(t *testing.T) {
	var p *schema.Provider
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_cmpv2"
	resourceBackend := resourceType + ".test"
	dataName := "data.vault_pki_secret_backend_config_cmpv2.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion1185)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigCMPV2Complete(backend, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDefaultPathPolicy, "role:cmpv2-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.%", "1"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.accessor", "test"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldEnableSentinelParsing, "true"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAuditFields+".#", "20"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDisabledValidations+".#", "2"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDisabledValidations+".0", "DisableMatchingKeyIdValidation"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldDisabledValidations+".1", "DisableCertTimeValidation"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldLastUpdated),

					// Validate that the data property can read back everything filled in
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDefaultPathPolicy, "role:cmpv2-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".#", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.%", "1"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.%", "2"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.accessor", "test"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuthenticators+".0.cert.cert_role", "a-role"),
					resource.TestCheckResourceAttr(dataName, consts.FieldEnableSentinelParsing, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldAuditFields+".#", "20"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisabledValidations+".0", "DisableMatchingKeyIdValidation"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisabledValidations+".1", "DisableCertTimeValidation"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
			testutil.GetImportTestStep(resourceBackend, false, nil),
		},
	})
}

func testAccPKISecretBackendConfigCMPV2Complete(pkiPath string, post1184 bool) string {
	post1184Config := `disabled_validations = ["DisableMatchingKeyIdValidation", "DisableCertTimeValidation"]`
	if !post1184 {
		post1184Config = ""
	}
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_role" "cmpv2_role" {
  backend = vault_mount.test.path
  name = "cmpv2-role"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_role" "cmpv2_role_2" {
  backend = vault_mount.test.path
  name = "cmpv2-role-2"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_config_cmpv2" "test" {
  backend = vault_mount.test.path
  enabled = true
  default_path_policy = format("role:%%s", vault_pki_secret_backend_role.cmpv2_role.name)
  authenticators { 
	cert = { "accessor" = "test", "cert_role" = "a-role" }
  }	
  enable_sentinel_parsing = true
  audit_fields = ["csr", "common_name", "alt_names", "ip_sans", "uri_sans", "other_sans",
                  "signature_bits", "exclude_cn_from_sans", "ou", "organization", "country", 
                  "locality", "province", "street_address", "postal_code", "serial_number",
                  "use_pss", "key_type", "key_bits", "add_basic_constraints"]
  %s
}

data "vault_pki_secret_backend_config_cmpv2" "test" {
  backend = vault_pki_secret_backend_config_cmpv2.test.backend	
}
`, pkiPath, post1184Config)
}

func testAccPKISecretBackendConfigCMPV2Disabled(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_config_cmpv2" "test" {
  backend = vault_mount.test.path
}

data "vault_pki_secret_backend_config_cmpv2" "test" {
  backend = vault_pki_secret_backend_config_cmpv2.test.backend	
}
`, path)
}
