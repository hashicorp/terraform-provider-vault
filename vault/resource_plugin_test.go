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

func TestPlugin(t *testing.T) {
	const (
		typ     = "auth"
		version = "v1.0.0"
		sha     = "sha256"
		cmd     = "command"
		args    = "--foo"
		env     = "FOO=BAR"
		img     = "ociImage"
		runtime = "runtime"
	)

	destName := acctest.RandomWithPrefix("tf-plugin")

	resourceName := "vault_plugin.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		Steps: []resource.TestStep{
			{
				Config: testPluginConfig(typ, destName, version, sha, cmd, args, env, img, runtime),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldType, typ),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVersion, version),
					resource.TestCheckResourceAttr(resourceName, fieldSHA256, sha),
					resource.TestCheckResourceAttr(resourceName, fieldCommand, cmd),
					resource.TestCheckResourceAttr(resourceName, fieldArgs, args),
					resource.TestCheckResourceAttr(resourceName, fieldEnv, env),
					resource.TestCheckResourceAttr(resourceName, fieldOCIImage, img),
					resource.TestCheckResourceAttr(resourceName, fieldRuntime, runtime),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testPluginConfig(pluginType, name, version, sha256, command, args, env, ociImage, runtime string) string {
	ret := fmt.Sprintf(`
resource "vault_plugin" "test" {
  type      = "%s"
  name      = "%s"
  version   = "%s"
  sha256    = "%s"
  command   = "%s"
  args      = %s
  env       = %s
  oci_image = "%s"
  runtime   = "%s"
}
`, pluginType, name, version, sha256, command, args, env, ociImage, runtime)

	return ret
}
