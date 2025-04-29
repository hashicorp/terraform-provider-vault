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

func TestAccDataSourcePKISecretConfigCMPV2(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")
	dataName := "data.vault_pki_secret_backend_config_cmpv2.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKISecretEmptyCMPV2ConfigDataSource(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldEnabled),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldEnableSentinelParsing),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
		},
	})
}

func testPKISecretEmptyCMPV2ConfigDataSource(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

data "vault_pki_secret_backend_config_cmpv2" "test" {
  backend = vault_mount.test.path
}`, path)
}
