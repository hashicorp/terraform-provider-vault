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
	serviceAccountNames := "foo, bar, baz"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendLibrarySetConfig_defaults(bindDN, bindPass, url, setName, serviceAccountNames),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSetName, setName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames, serviceAccountNames),
				),
			},
			{
				Config: testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, serviceAccountNames, "20", "40"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSetName, creationLDIF+"\n"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames, serviceAccountNames),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "40"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldPath),
		},
	})
}

// testLDAPSecretBackendLibrarySetConfig_defaults sets up default and required
// fields.
func testLDAPSecretBackendLibrarySetConfig_defaults(bindDN, bindPass, url, setName, serviceAccountNames string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  description = "test description"
  binddn      = "%s"
  bindpass    = "%s"
  url         = "%s"
}

resource "vault_ldap_secret_backend_library_set" "set" {
  path                  = vault_ldap_secret_backend.test.path
  set_name              = "%s"
  service_account_names = "%s"
}
`, bindDN, bindPass, url, setName, serviceAccountNames)
}

func testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, serviceAccountNames, ttl, maxTTL string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  description = "test description"
  binddn      = "%s"
  bindpass    = "%s"
  url         = "%s"
}

resource "vault_ldap_secret_backend_library_set" "set" {
  path                  = vault_ldap_secret_backend.test.path
  set_name              = "%s"
  service_account_names = "%s"
  ttl                   = %s
  max_ttl               = %s
}
`, bindDN, bindPass, url, setName, serviceAccountNames, ttl, maxTTL)
}
