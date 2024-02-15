// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFAPingIDBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("mfa-pingid")
	// Base64 Encoded string taken from Vault repo example
	settingsFile := "I0F1dG8tR2VuZXJhdGVkIGZyb20gUGluZ09uZSwgZG93bmxvYWRlZCBieSBpZD1bU1NPXSBlbWFpbD1baGFtaWRAaGFzaGljb3JwLmNvbV0KI1dlZCBEZWMgMTUgMTM6MDg6NDQgTVNUIDIwMjEKdXNlX2Jhc2U2NF9rZXk9YlhrdGMyVmpjbVYwTFd0bGVRPT0KdXNlX3NpZ25hdHVyZT10cnVlCnRva2VuPWxvbC10b2tlbgppZHBfdXJsPWh0dHBzOi8vaWRweG55bDNtLnBpbmdpZGVudGl0eS5jb20vcGluZ2lkCm9yZ19hbGlhcz1sb2wtb3JnLWFsaWFzCmFkbWluX3VybD1odHRwczovL2lkcHhueWwzbS5waW5naWRlbnRpdHkuY29tL3BpbmdpZAphdXRoZW50aWNhdG9yX3VybD1odHRwczovL2F1dGhlbnRpY2F0b3IucGluZ29uZS5jb20vcGluZ2lkL3BwbQ=="
	resourceName := "vault_mfa_pingid.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testMFAPingIDConfig(path, settingsFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", path),
					resource.TestCheckResourceAttr(resourceName, "username_format", "user@example.com"),
					resource.TestCheckResourceAttr(resourceName, "type", "pingid"),
					resource.TestCheckResourceAttr(resourceName, "use_signature", "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespaceID, ""),
					resource.TestCheckResourceAttr(resourceName, "settings_file_base64", settingsFile),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldMountAccessor, "username_format", "settings_file_base64"},
			},
		},
	})
}

func testMFAPingIDConfig(path, file string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_mfa_pingid" "test" {
  name                  = %q
  mount_accessor        = vault_auth_backend.userpass.accessor
  username_format       = "user@example.com"
  settings_file_base64	= %q
}
`, acctest.RandomWithPrefix("userpass"), path, file)
}
