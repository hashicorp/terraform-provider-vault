// Copyright IBM Corp. 2016, 2025
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

func TestAccDataSourcePKISecretConfigEst(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")
	dataName := "data.vault_pki_secret_backend_config_est.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		Steps: []resource.TestStep{
			{
				// Note this is more thoroughly tested within TestAccPKISecretBackendConfigEst_basic
				// we don't want to start having test failures if Vault changes default values.
				Config: testPKISecretEmptyEstConfigDataSource(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldEnabled),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldDefaultMount),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldEnableSentinelParsing),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastUpdated),
				),
			},
		},
	})
}

func testPKISecretEmptyEstConfigDataSource(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

data "vault_pki_secret_backend_config_est" "test" {
  backend = vault_mount.test.path
}`, path)
}
