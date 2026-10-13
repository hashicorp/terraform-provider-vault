// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func TestAccDataSourceTransitSecretBackendKeyVersion(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	v1 := "data.vault_transit_secret_backend_key_version.v1"
	v2 := "data.vault_transit_secret_backend_key_version.v2"
	latest := "data.vault_transit_secret_backend_key_version.latest"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion220)
		},
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyVersionConfig(name, backend, "ecdsa-p256", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(v1, consts.FieldType, "ecdsa-p256"),
					resource.TestCheckResourceAttr(v1, consts.FieldVersion, "1"),
					resource.TestCheckResourceAttrSet(v1, consts.FieldPublicKey),
					resource.TestCheckResourceAttr(v1, consts.FieldSupportsSigning, "true"),
					resource.TestCheckResourceAttr(v1, consts.FieldSupportsEncryption, "false"),
					// with no version set, the latest version is read
					resource.TestCheckResourceAttr(latest, consts.FieldType, "ecdsa-p256"),
					resource.TestCheckResourceAttr(latest, consts.FieldVersion, "1"),
				),
			},
			{
				// after rotating to a new algorithm, each version keeps its own type
				Config: testTransitSecretBackendKeyVersionConfig(name, backend, "ml-dsa", `parameter_set = "65"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(v1, consts.FieldType, "ecdsa-p256"),
					resource.TestCheckResourceAttr(v1, consts.FieldVersion, "1"),
					resource.TestCheckResourceAttr(v2, consts.FieldType, "ml-dsa"),
					resource.TestCheckResourceAttr(v2, consts.FieldVersion, "2"),
					resource.TestCheckResourceAttr(v2, consts.FieldParameterSet, "65"),
					resource.TestCheckResourceAttrSet(v2, consts.FieldPublicKey),
					resource.TestCheckResourceAttr(latest, consts.FieldType, "ml-dsa"),
					resource.TestCheckResourceAttr(latest, consts.FieldVersion, "2"),
				),
			},
		},
	})
}

func testTransitSecretBackendKeyVersionConfig(name, path, keyType, extra string) string {
	config := testTransitSecretBackendKeyConfig_cryptoAgility(name, path, keyType, extra)
	return config + fmt.Sprintf(`
data "vault_transit_secret_backend_key_version" "v1" {
  backend = vault_mount.transit.path
  name    = vault_transit_secret_backend_key.test.name
  version = 1
}

data "vault_transit_secret_backend_key_version" "latest" {
  backend = vault_mount.transit.path
  name    = vault_transit_secret_backend_key.test.name

  depends_on = [vault_transit_secret_backend_key.test]
}
%s
`, testTransitSecretBackendKeyVersionV2(keyType))
}

// the second version only exists after the key has been rotated
func testTransitSecretBackendKeyVersionV2(keyType string) string {
	if keyType != "ml-dsa" {
		return ""
	}
	return `
data "vault_transit_secret_backend_key_version" "v2" {
  backend = vault_mount.transit.path
  name    = vault_transit_secret_backend_key.test.name
  version = 2
}
`
}
