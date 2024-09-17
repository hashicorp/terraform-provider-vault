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

func TestAccDataSourceTransitSecretKey(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-transit-backend")
	keyName := acctest.RandomWithPrefix("tf-test-transit-key")
	dataName := "data.vault_transit_secret_backend_key.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretKeyDataSource(backend, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(dataName, "type", "rsa-4096"),
					resource.TestCheckResourceAttr(dataName, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(dataName, "exportable", "true"),
					resource.TestCheckResourceAttr(dataName, "keys.0.name", "rsa-4096"),
					resource.TestCheckResourceAttr(dataName, "keys.0.certificate_chain", ""),
					resource.TestCheckResourceAttrSet(dataName, "keys.0.creation_time"),
					resource.TestCheckResourceAttrSet(dataName, "keys.0.public_key"),
				),
			},
		},
	})
}

func testTransitSecretKeyDataSource(path, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "transit"
    description = "Transit engine mount"
}

resource "vault_transit_secret_backend_key" "test" {
  backend               = vault_mount.test.path
  name                  = "%s"
  type                  = "rsa-4096"
  deletion_allowed      = true
  exportable            = true
}

data "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.test.path
  name    = vault_transit_secret_backend_key.test.name
}`, path, keyName)
}
