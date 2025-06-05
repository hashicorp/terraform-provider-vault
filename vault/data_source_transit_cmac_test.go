// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

var cmacBlocks = `
data "vault_transit_cmac" "test" {
    path        = vault_mount.test.path
    name        = vault_transit_secret_backend_key.test.name
	input       = "aGVsbG8gd29ybGQuCg=="
}
data "vault_transit_verify" "test" {
    path        = vault_mount.test.path
    name        = vault_transit_secret_backend_key.test.name
	input       = "aGVsbG8gd29ybGQuCg=="
    cmac        = data.vault_transit_cmac.test.cmac
}
`

var cmacBatchInputBlocks = `
data "vault_transit_cmac" "test" {
    path        = vault_mount.test.path
    name        = vault_transit_secret_backend_key.test.name
	batch_input = [
		{
		  input = "adba32=="
		},
		{
		  input = "aGVsbG8gd29ybGQuCg=="
		}
    ]
}
data "vault_transit_verify" "test" {
    path        = vault_mount.test.path
    name        = vault_transit_secret_backend_key.test.name
	input       = "aGVsbG8gd29ybGQuCg=="
    cmac        = data.vault_transit_cmac.test.cmac
	batch_input = [
		{
		  input = "adba32=="
          cmac  = data.vault_transit_cmac.test.batch_results.0.cmac
		},
		{
		  input = "aGVsbG8gd29ybGQuCg=="
          cmac  = data.vault_transit_cmac.test.batch_results.1.cmac
		}
    ]
}
`

func TestDataSourceTransitCMAC(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	cmacResourceName := "data.vault_transit_cmac.test"
	verifyResourceName := "data.vault_transit_verify.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		Steps: []resource.TestStep{
			{
				Config: cmacConfig(backend, "aes128-cmac", cmacBlocks),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmacResourceName, "cmac"),
					resource.TestCheckResourceAttr(verifyResourceName, "valid", "true"),
				),
			},
			{
				Config: cmacConfig(backend, "aes128-cmac", cmacBatchInputBlocks),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmacResourceName, "batch_results.#"),
					resource.TestCheckResourceAttr(verifyResourceName, "batch_results.0.valid", "true"),
					resource.TestCheckResourceAttr(verifyResourceName, "batch_results.1.valid", "true"),
				),
			},
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypeTransit, consts.FieldPath),
	})
}

func cmacConfig(backend, keyType, blocks string) string {
	baseConfig := `
resource "vault_mount" "test" {
  path        = "%s"
  type        = "transit"
  description = "This is an example mount"
}

resource "vault_transit_secret_backend_key" "test" {
  name  		   = "test"
  backend 		   = vault_mount.test.path
  deletion_allowed = true
  type             = "%s"
}

%s
`
	return fmt.Sprintf(baseConfig, backend, keyType, blocks)
}
