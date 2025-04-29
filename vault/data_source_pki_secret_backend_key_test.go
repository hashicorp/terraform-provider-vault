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

func TestAccDataSourcePKISecretKey(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")
	keyName := acctest.RandomWithPrefix("tf-test-pki-key")
	dataName := "data.vault_pki_secret_backend_key.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKISecretKeyDataSource(backend, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldKeyName, keyName),
					resource.TestCheckResourceAttr(dataName, consts.FieldKeyType, "rsa"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldKeyID),
				),
			},
		},
	})
}

func testPKISecretKeyDataSource(path, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_key" "test" {
  backend  = vault_mount.test.path
  type     = "internal"
  key_name = "%s"
  key_type = "rsa"
  key_bits = "4096"
}

data "vault_pki_secret_backend_key" "test" {
  backend = vault_mount.test.path
  key_ref = vault_pki_secret_backend_key.test.key_id
}`, path, keyName)
}
