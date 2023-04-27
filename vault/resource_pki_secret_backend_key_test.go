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

func TestAccPKISecretBackendKey_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_key"
	resourceName := resourceType + ".test"

	keyName := acctest.RandomWithPrefix("tf-pki-key")
	updatedKeyName := acctest.RandomWithPrefix("tf-pki-key-updated")

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendKey_basic(mount, keyName, "rsa", "2048"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "2048"),
				),
			},
			{
				Config: testAccPKISecretBackendKey_basic(mount, updatedKeyName, "rsa", "2048"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, updatedKeyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "2048"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldType, consts.FieldKeyBits},
			},
		},
	})
}

func testAccPKISecretBackendKey_basic(path, keyName, keyType, keyBits string) string {
	return fmt.Sprintf(`
resource "vault_mount" "pki" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_key" "test" {
  mount    = vault_mount.pki.path
  type     = "exported"
  key_name = "%s"
  key_type = "%s"
  key_bits = "%s"
}`, path, keyName, keyType, keyBits)
}
