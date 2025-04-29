// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPluginPinnedVersion(t *testing.T) {
	var p *schema.Provider
	const (
		typ     = "auth"
		version = "1.0.0"
	)

	destName := acctest.RandomWithPrefix("tf-plugin-pinned-version")

	resourceName := "vault_plugin_pinned_version.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.SkipTestEnvUnset(t, envPluginCommand)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		Steps: []resource.TestStep{
			{
				Config: testPluginPinnedVersionConfig(typ, destName, version),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldType, typ),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVersion, "v"+version),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testPluginPinnedVersionConfig(pluginType, name, version string) string {
	sha256 := strings.Repeat("01234567", 8)

	ret := fmt.Sprintf(`
%s

resource "vault_plugin_pinned_version" "test" {
  type      = vault_plugin.test.type
  name      = vault_plugin.test.name
  version   = vault_plugin.test.version
}
`, testPluginConfig(pluginType, name, version, sha256, os.Getenv(envPluginCommand), `["--arg"]`, `["foo=bar"]`))

	return ret
}
