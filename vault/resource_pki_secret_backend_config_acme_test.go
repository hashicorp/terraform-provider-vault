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

func TestPkiSecretBackendConfigACME_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("pki-root")
	resourceType := "vault_pki_secret_backend_config_acme"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendConfigACME(backend, "sign-verbatim", "*", "*", "not-required", "",
					false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "sign-verbatim"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "not-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, ""),
				),
			},
			{
				Config: testPkiSecretBackendConfigACME(backend, "forbid", "test", "*", "new-account-required",
					"1.1.1.1:8443", true, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "forbid"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "new-account-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, "1.1.1.1:8443"),
				),
			},
			{
				Config: testPkiSecretBackendConfigACME(backend, "role:test", "*", "*", "always-required", "",
					true, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "role:test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowRoleExtKeyUsage, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "always-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, ""),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testPkiSecretBackendConfigACME(path, default_directory_policy, allowed_roles, allowed_issuers,
	eab_policy, dns_resolver string, enabled, allow_role_ext_key_usage bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "pki"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
}

resource "vault_pki_secret_backend_config_cluster" "test" {
  backend  = vault_mount.test.path
  path     = "http://127.0.0.1:8200/v1/${vault_mount.test.path}"
  aia_path = "http://127.0.0.1:8200/v1/${vault_mount.test.path}"
}

resource "vault_pki_secret_backend_role" "test" {
  backend = vault_pki_secret_backend_root_cert.test.backend
  name    = "test"
}

resource "vault_pki_secret_backend_config_acme" "test" {
  backend                  = vault_mount.test.path
  enabled                  = "%t"
  allowed_issuers          = ["%s"]
  allowed_roles            = ["%s"]
  allow_role_ext_key_usage = "%t"
  default_directory_policy = "%s"
  dns_resolver             = "%s"
  eab_policy               = "%s"
}`, path, enabled, allowed_issuers, allowed_roles, allow_role_ext_key_usage,
		default_directory_policy, dns_resolver, eab_policy)
}
