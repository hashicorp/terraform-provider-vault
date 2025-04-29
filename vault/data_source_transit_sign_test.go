// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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
		}
    ]
`

var signInputConfig = "input = \"aGVsbG8gd29ybGQuCg==\""

func TestDataSourceTransitSign(t *testing.T) {
	var p *schema.Provider
	resourceName := "data.vault_transit_sign.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: signVerifyConfig("ecdsa-p256", "", signBlock(signInputConfig)),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "signature"),
			},
			{
				Config: signVerifyConfig("ecdsa-p256", "", signBlock(signBatchConfig)),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "batch_results.#"),
			},
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypeTransit, consts.FieldPath),
	})
}

func signVerifyConfig(keyType, keyConfig, blocks string) string {
	baseConfig := `
resource "vault_mount" "test" {
  path        = "transit"
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
	return fmt.Sprintf(baseConfig, keyType, keyConfig, blocks)
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
