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

var verifyBatchConfig = `
    batch_input = [
		{
		  input = "adba32=="
		  context = "abcd"
		  signature = data.vault_transit_sign.test.batch_results.0.signature
		},
		{
		  input = "aGVsbG8gd29ybGQuCg=="
		  context = "efgh"
		  signature = data.vault_transit_sign.test.batch_results.1.signature
		}
    ]
`

var verifyInputConfig = `input = "aGVsbG8gd29ybGQuCg=="
signature = data.vault_transit_sign.test.signature 
`

func TestDataSourceTransitVerify(t *testing.T) {
	resourceName := "data.vault_transit_sign.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: signVerifyConfig("ecdsa-p256", "", verifyTestConfig(signInputConfig, verifyInputConfig)),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "signature"),
			},
			{
				Config: signVerifyConfig("ecdsa-p256", "", verifyTestConfig(signBatchConfig, verifyBatchConfig)),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "batch_results.#"),
			},
			{
				Config: signVerifyConfig("ml-dsa", "parameter_set = \"44\"", verifyTestConfig(signInputConfig, verifyInputConfig)),
				Check:  resource.TestCheckResourceAttrSet(resourceName, "signature"),
			},
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypeTransit, consts.FieldPath),
	})
}

func verifyBlock(input string) string {
	block := `
data "vault_transit_verify" "test" {
    path        = vault_mount.test.path
    name        = vault_transit_secret_backend_key.test.name
	%s
}
`

	return fmt.Sprintf(block, input)
}

func verifyTestConfig(signInput, verifyInput string) string {
	return signBlock(signInput) + verifyBlock(verifyInput)
}
