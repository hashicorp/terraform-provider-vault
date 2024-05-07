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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const envPluginCommand = "VAULT_PLUGIN_COMMAND"

func TestPlugin(t *testing.T) {
	const (
		typ     = "auth"
		version = "v1.0.0"
		args    = `["--foo"]`
		env     = `["FOO=BAR"]`

		argsUpdated = `["--bar"]`
		envUpdated  = `["FOO=BAZ"]`
	)

	destName := acctest.RandomWithPrefix("tf/plugin")

	resourceName := "vault_plugin.test"
	sha256 := strings.Repeat("01234567", 8)
	sha256Updated := strings.Repeat("12345678", 8)
	// VAULT_PLUGIN_COMMAND should be set to the name of the plugin executable
	// in the configured plugin_directory for Vault.
	cmd := os.Getenv(envPluginCommand)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.SkipTestEnvUnset(t, envPluginCommand)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
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
			{
				Config: testPluginConfig(typ, destName, version, sha256Updated, cmd, argsUpdated, envUpdated),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldType, typ),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVersion, version),
					resource.TestCheckResourceAttr(resourceName, fieldSHA256, sha256Updated),
					resource.TestCheckResourceAttr(resourceName, fieldCommand, cmd),
					testValidateList(resourceName, fieldArgs, []string{"--bar"}),
					testValidateList(resourceName, fieldEnv, []string{"FOO=BAZ"}),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "env"),
		},
	})
}

func testPluginConfig(pluginType, name, version, sha256, command, args, env string) string {
	return fmt.Sprintf(`
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

func TestPluginFromID(t *testing.T) {
	for name, tc := range map[string]struct {
		id      string
		typ     string
		name    string
		version string
	}{
		"auth":                             {"auth/version/v1.0.0/name/foo", "auth", "foo", "v1.0.0"},
		"secret":                           {"secret/version/v1.0.0/name/foo", "secret", "foo", "v1.0.0"},
		"database":                         {"database/version/v1.0.0/name/foo", "database", "foo", "v1.0.0"},
		"no version":                       {"auth/name/foo", "auth", "foo", ""},
		"weird version":                    {"auth/version/bad-semver/name/foo", "auth", "foo", "bad-semver"},
		"name with slashes":                {"auth/version/v1.0.0/name/foo/bar/baz", "auth", "foo/bar/baz", "v1.0.0"},
		"no version and name with slashes": {"auth/name/foo/bar/baz", "auth", "foo/bar/baz", ""},
		"missing type":                     {"version/v1.0.0/name/foo", "", "", ""},
		"invalid type":                     {"new-type/version/v1.0.0/name/foo", "", "", ""},
		"missing name":                     {"auth/version/v1.0.0", "", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			typ, name, version := pluginFromID(tc.id)
			if typ != tc.typ {
				t.Errorf("expected type %q, got %q", tc.typ, typ)
			}
			if name != tc.name {
				t.Errorf("expected name %q, got %q", tc.name, name)
			}
			if version != tc.version {
				t.Errorf("expected version %q, got %q", tc.version, version)
			}
		})
	}
}
