// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourcePKISecretKeys(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")
	keyName := acctest.RandomWithPrefix("tf-test-pki-key")
	dataName := "data.vault_pki_secret_backend_keys.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKISecretKeysDataSource(backend, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, "keys.#", "1"),
					resource.TestCheckResourceAttr(dataName, "key_info.%", "1"),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldKeyInfoJSON),
				),
			},
		},
	})
}

func testPKISecretKeysDataSource(path, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
  key_name    = "%s"
}

data "vault_pki_secret_backend_keys" "test" {
  backend     = vault_pki_secret_backend_root_cert.test.backend
}`, path, keyName)
}
