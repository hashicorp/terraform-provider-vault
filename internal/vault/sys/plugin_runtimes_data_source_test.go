package sys_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccPluginRuntimesDataSource(t *testing.T) {
	fullName := acctest.RandomWithPrefix("test-runtime-full")
	minimalName := acctest.RandomWithPrefix("test-runtime-minimal")
	dataSourceAll := "data.vault_plugin_runtimes.all"
	dataSourceContainers := "data.vault_plugin_runtimes.containers"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipTestAccEnt(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPluginRuntimesDataSourceConfig(fullName, minimalName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceAll, consts.FieldID, "plugin-runtimes"),
					resource.TestCheckResourceAttr(dataSourceContainers, consts.FieldID, "plugin-runtimes/container"),
					testAccCheckPluginRuntimesContains(dataSourceAll, fullName, map[string]string{
						"type":          "container",
						"oci_runtime":   "runc",
						"cgroup_parent": "/vault/plugins",
						"rootless":      "true",
					}),
					testAccCheckPluginRuntimesContains(dataSourceAll, minimalName, map[string]string{
						"type":     "container",
						"rootless": "false",
					}),
				),
			},
		},
	})
}

func TestAccPluginRuntimesDataSource_InvalidTypePassthrough(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipTestAccEnt(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPluginRuntimesDataSourceConfigInvalidType(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_plugin_runtimes.test", consts.FieldID, "plugin-runtimes/invalid"),
				),
			},
		},
	})
}

func TestAccPluginRuntimesDataSource_NS(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPluginRuntimesDataSourceConfigNS(ns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_plugin_runtimes.test", consts.FieldID, "plugin-runtimes"),
				),
			},
		},
	})
}

func testAccCheckPluginRuntimesContains(resourceName, runtimeName string, expected map[string]string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state: %s", resourceName)
		}

		attrs := rs.Primary.Attributes
		count := 0
		if rawCount, ok := attrs["runtimes.#"]; ok {
			_, _ = fmt.Sscanf(rawCount, "%d", &count)
		}

		for i := 0; i < count; i++ {
			prefix := fmt.Sprintf("runtimes.%d.", i)
			if attrs[prefix+"name"] != runtimeName {
				continue
			}

			for key, want := range expected {
				if got := attrs[prefix+key]; got != want {
					return fmt.Errorf("runtime %q attribute %q mismatch: got %q want %q", runtimeName, key, got, want)
				}
			}

			return nil
		}

		return fmt.Errorf("runtime %q not found in %s", runtimeName, resourceName)
	}
}

func testAccPluginRuntimesDataSourceConfig(fullName, minimalName string) string {
	return fmt.Sprintf(`
resource "vault_plugin_runtime" "full" {
  type          = "container"
  name          = %q
  oci_runtime   = "runc"
  cgroup_parent = "/vault/plugins"
  cpu_nanos     = 1000000000
  memory_bytes  = 536870912
  rootless      = true
}

resource "vault_plugin_runtime" "minimal" {
  type = "container"
  name = %q
}

data "vault_plugin_runtimes" "all" {
  depends_on = [
    vault_plugin_runtime.full,
    vault_plugin_runtime.minimal,
  ]
}

data "vault_plugin_runtimes" "containers" {
  type = "container"

  depends_on = [
    vault_plugin_runtime.full,
    vault_plugin_runtime.minimal,
  ]
}
`, fullName, minimalName)
}

func testAccPluginRuntimesDataSourceConfigInvalidType() string {
	return `
data "vault_plugin_runtimes" "test" {
  type = "invalid"
}
`
}

func testAccPluginRuntimesDataSourceConfigNS(ns string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

data "vault_plugin_runtimes" "test" {
  namespace = vault_namespace.test.path
}
`, ns)
}
