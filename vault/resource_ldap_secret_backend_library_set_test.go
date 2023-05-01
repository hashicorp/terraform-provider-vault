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

func TestAccLDAPSecretBackendLibrarySet(t *testing.T) {
	setName := acctest.RandomWithPrefix("tf-test-ldap-library-set")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	resourceType := "vault_ldap_secret_backend_library_set"
	resourceName := resourceType + ".set"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendLibrarySetConfig_defaults(bindDN, bindPass, url, setName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, setName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".0", "bob"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".1", "alice"),
				),
			},
			{
				Config: testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, "20", "40", `"bob"`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, setName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".0", "bob"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "40"),
				),
			},
			{
				Config: testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, "20", "40", `"bob","foo"`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, setName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".0", "bob"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".1", "foo"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "40"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldPath, consts.FieldName),
		},
	})
}

// testLDAPSecretBackendLibrarySetConfig_defaults sets up default and required
// fields.
func testLDAPSecretBackendLibrarySetConfig_defaults(bindDN, bindPass, url, setName string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  description = "test description"
  binddn      = "%s"
  bindpass    = "%s"
  url         = "%s"
  userdn      = "ou=users,dc=example,dc=org"
}

resource "vault_ldap_secret_backend_library_set" "set" {
  path                  = vault_ldap_secret_backend.test.path
  name                  = "%s"
  service_account_names = ["bob","alice"]
}
`, bindDN, bindPass, url, setName)
}

func testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, ttl, maxTTL, saNames string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  description = "test description"
  binddn      = "%s"
  bindpass    = "%s"
  url         = "%s"
  userdn      = "ou=users,dc=example,dc=org"
}

resource "vault_ldap_secret_backend_library_set" "set" {
  path                  = vault_ldap_secret_backend.test.path
  name                  = "%s"
  ttl                   = %s
  max_ttl               = %s
  service_account_names = [%s]
}
`, bindDN, bindPass, url, setName, ttl, maxTTL, saNames)
}
