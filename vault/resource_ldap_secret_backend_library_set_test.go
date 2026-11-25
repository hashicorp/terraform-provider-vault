// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestLDAPSecretBackendLibrarySetDataIncludesFalseBoolean(t *testing.T) {
	r := ldapSecretBackendLibrarySetResource()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		consts.FieldName:                      "test",
		consts.FieldServiceAccountNames:       []interface{}{"bob"},
		consts.FieldDisableCheckInEnforcement: false,
	})

	data := ldapSecretBackendLibrarySetData(d)
	got, ok := data[consts.FieldDisableCheckInEnforcement]
	if !ok {
		t.Fatal("disable_check_in_enforcement was omitted from the write payload")
	}
	if got != false {
		t.Fatalf("disable_check_in_enforcement = %#v, want false", got)
	}
}

func TestAccLDAPSecretBackendLibrarySet(t *testing.T) {
	setName := acctest.RandomWithPrefix("tf-test-ldap-library-set")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	resourceType := "vault_ldap_secret_backend_library_set"
	resourceName := resourceType + ".set"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendLibrarySetConfig_defaults(bindDN, bindPass, url, setName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, setName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".0", "bob"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".1", "alice"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableCheckInEnforcement, "false"),
				),
			},
			{
				Config: testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, `"bob"`, 20, 40, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, setName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".0", "bob"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "40"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableCheckInEnforcement, "true"),
				),
			},
			{
				Config: testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, `"bob","foo"`, 20, 40, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, setName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".0", "bob"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountNames+".1", "foo"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "40"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableCheckInEnforcement, "true"),
				),
			},
			{
				Config: testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, `"bob","foo"`, 20, 40, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableCheckInEnforcement, "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldName),
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
  mount                 = vault_ldap_secret_backend.test.path
  name                  = "%s"
  service_account_names = ["bob","alice"]
}
`, bindDN, bindPass, url, setName)
}

func testLDAPSecretBackendLibrarySetConfig(bindDN, bindPass, url, setName, saNames string, ttl, maxTTL int, disableCheckInEnforcement bool) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  description = "test description"
  binddn      = "%s"
  bindpass    = "%s"
  url         = "%s"
  userdn      = "ou=users,dc=example,dc=org"
}

resource "vault_ldap_secret_backend_library_set" "set" {
  mount                 = vault_ldap_secret_backend.test.path
  name                  = "%s"
  ttl                   = %d
  max_ttl               = %d
  service_account_names = [%s]

  disable_check_in_enforcement = %t
}
`, bindDN, bindPass, url, setName, ttl, maxTTL, saNames, disableCheckInEnforcement)
}
