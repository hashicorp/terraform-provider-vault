// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const envPluginCommand = "VAULT_PLUGIN_COMMAND"

func TestPlugin(t *testing.T) {
	const (
		typ     = "auth"
		version = "v1.0.0"
		args    = `["--foo"]`
		env     = `["FOO=BAR"]`
	)

	destName := acctest.RandomWithPrefix("tf-plugin")

	resourceName := "vault_plugin.test"
	sha256 := strings.Repeat("01234567", 8)
	cmd := os.Getenv(envPluginCommand)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.SkipTestEnvUnset(t, envPluginCommand)
		},
		Steps: []resource.TestStep{
			{
				Config: testPluginConfig(typ, destName, version, sha256, cmd, args, env),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldType, typ),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVersion, version),
					resource.TestCheckResourceAttr(resourceName, fieldSHA256, sha256),
					resource.TestCheckResourceAttr(resourceName, fieldCommand, cmd),
					testValidateList(resourceName, fieldArgs, []string{"--foo"}),
					testValidateList(resourceName, fieldEnv, []string{"FOO=BAR"}),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "env"),
		},
	})
}

func testPluginConfig(pluginType, name, version, sha256, command, args, env string) string {
	ret := fmt.Sprintf(`
resource "vault_plugin" "test" {
  type      = "%s"
  name      = "%s"
  version   = "%s"
  sha256    = "%s"
  command   = "%s"
  args      = %s
  env       = %s
}
`, pluginType, name, version, sha256, command, args, env)

	return ret
}

func testValidateList(resourceName, attr string, expected []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		attrs := rs.Primary.Attributes

		if attrs[attr+".#"] != strconv.Itoa(len(expected)) {
			return fmt.Errorf("expected %s to have %d elements, got %s", attr, len(expected), attrs[attr+".#"])
		}

		for i, exp := range expected {
			if actual := attrs[attr+"."+strconv.Itoa(i)]; actual != exp {
				return fmt.Errorf("expected %s[%d] to be %q, got %q", attr, i, exp, actual)
			}
		}

		return nil
	}
}
