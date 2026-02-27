// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

var signBatchConfig = `
    batch_input = [
		{
		  input = "adba32=="
		  context = "abcd"
		},
		{
		  input = "aGVsbG8gd29ybGQuCg=="
		  context = "efgh"
		},
		{
		  input = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
		  prehashed = true
		},
		{
		  input = "invalid-input"
		}
    ]
`

var signInputConfig = "input = \"aGVsbG8gd29ybGQuCg==\""

func TestDataSourceTransitSign(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	resourceName := "data.vault_transit_sign.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: signVerifyConfig(backend, "ecdsa-p256", "", signBlock(signInputConfig)),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "signature"),
			},
			{
				Config: signVerifyConfig(backend, "ecdsa-p256", "", signBlock(signBatchConfig)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "batch_results.#", "4"),
					resource.TestCheckResourceAttrSet(resourceName, "batch_results.0.signature"),
					resource.TestCheckResourceAttrSet(resourceName, "batch_results.1.signature"),
					resource.TestCheckResourceAttrSet(resourceName, "batch_results.2.signature"),
					resource.TestCheckResourceAttrSet(resourceName, "batch_results.3.error"),
				),
			},
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypeTransit, consts.FieldPath),
	})
}

func signVerifyConfig(backend, keyType, keyConfig, blocks string) string {
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
  %s
}

%s
`
	return fmt.Sprintf(baseConfig, backend, keyType, keyConfig, blocks)
}

func signBlock(input string) string {
	block := `
data "vault_transit_sign" "test" {
    path        = vault_mount.test.path
    name        = vault_transit_secret_backend_key.test.name
	%s
}
`

	return fmt.Sprintf(block, input)
}
