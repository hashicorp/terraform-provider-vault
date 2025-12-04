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
		},
		{
		  input = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
		  prehashed = true
		  signature = data.vault_transit_sign.test.batch_results.2.signature
		},
		{
		  input = "aGVsbG8gd29ybGQuCg=="
		  signature = "bad-input"
		}
    ]
`

var verifyInputConfig = `input = "aGVsbG8gd29ybGQuCg=="
signature = data.vault_transit_sign.test.signature 
`

func TestDataSourceTransitVerify(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	signResourceName := "data.vault_transit_sign.test"
	verifyResourceName := "data.vault_transit_verify.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: signVerifyConfig(backend, "ecdsa-p256", "", verifyTestConfig(signInputConfig, verifyInputConfig)),
				Check:  resource.TestCheckResourceAttrSet(signResourceName, "signature"),
			},
			{
				Config: signVerifyConfig(backend, "ecdsa-p256", "", verifyTestConfig(signBatchConfig, verifyBatchConfig)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(signResourceName, "batch_results.#", "4"),
					resource.TestCheckResourceAttr(verifyResourceName, "batch_results.#", "4"),
					resource.TestCheckResourceAttr(verifyResourceName, "batch_results.0.valid", "true"),
					resource.TestCheckResourceAttr(verifyResourceName, "batch_results.1.valid", "true"),
					resource.TestCheckResourceAttr(verifyResourceName, "batch_results.2.valid", "true"),
					resource.TestCheckResourceAttr(verifyResourceName, "batch_results.3.valid", "false"),
					resource.TestCheckResourceAttrSet(verifyResourceName, "batch_results.3.error"),
				),
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
