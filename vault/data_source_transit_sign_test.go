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

var config = `
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

data "vault_transit_sign" "test" {
    path        = vault_mount.test.path
    name        = vault_transit_secret_backend_key.test.name
	%s
}
`

var batchConfig = `
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

var inputConfig = "input = \"aGVsbG8gd29ybGQuCg==\""

func TestDataSourceTransitSign(t *testing.T) {
	resourceName := "data.vault_transit_sign.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: buildConfig("ecdsa-p256", "", inputConfig),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "signature"),
			},
			{
				Config: buildConfig("ecdsa-p256", "", batchConfig),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "batch_results.#"),
			},
			{
				Config: buildConfig("ml-dsa", "parameter_set = \"44\"", inputConfig),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "signature"),
			},
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypeTransit, consts.FieldPath),
	})
}

func buildConfig(keyType, keyConfig, input string) string {
	return fmt.Sprintf(config, keyType, keyConfig, input)
}
