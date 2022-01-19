package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/vault/api"
)

func TestAccKvV2Config_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("kv-v2-config-test")
	cas_required := true
	delete_version_after := "1h1m1s"
	max_versions := 4

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKvV2ConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKvV2Config_full(backend, max_versions, cas_required, delete_version_after),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(max_versions)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", cas_required)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"delete_version_after", delete_version_after),
				),
			},
			{
				ResourceName:      "vault_kv_v2_config.kv-config",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
func TestAccKvV2Config_fullUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("kv-v2-config-test")
	cas_required := false
	delete_version_after := "2h2m2s"
	max_versions := 3
	new_max_versions := 10
	new_delete_versions_after := "1h0m0s"
	max_version_for_basic := 1
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKvV2ConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKvV2Config_full(backend, max_versions, cas_required, delete_version_after),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(max_versions)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", cas_required)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"delete_version_after", delete_version_after),
				),
			},
			// change max_versions
			{
				Config: testAccKvV2Config_full(backend, new_max_versions, cas_required, delete_version_after),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(new_max_versions)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", cas_required)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"delete_version_after", delete_version_after),
				),
			},
			// change cas_required,delete_version_after
			{
				Config: testAccKvV2Config_full(backend, new_max_versions, !cas_required, new_delete_versions_after),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(new_max_versions)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", !cas_required)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"delete_version_after", new_delete_versions_after),
				),
			},
			{
				Config: testAccKvV2Config_basic(backend, max_version_for_basic),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(max_version_for_basic)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", false)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"delete_version_after", "0s"),
				),
			},
		},
	})
}
func testAccKvV2Config_full(path string, max_versions int, cas_required bool, delete_version_after string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kv" {
  type = "kv-v2"
  path = %q
}

resource "vault_kv_v2_config" "kv-config" {
  path = vault_mount.kv.path
  max_versions = %d
  cas_required = %t
  delete_version_after = %q
}`, path, max_versions, cas_required, delete_version_after)
}

func testAccKvV2Config_basic(path string, max_versions int) string {
	return fmt.Sprintf(`
resource "vault_mount" "kv" {
  type = "kv-v2"
  path = %q
}

resource "vault_kv_v2_config" "kv-config" {
  path = vault_mount.kv.path
  max_versions = %d
}`, path, max_versions)
}

func testAccCheckKvV2ConfigDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kv_v2_config" {
			continue
		}
		secret, err := client.Logical().Read(kvV2MountPathConfigPath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for kv-v2 config %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("vault_kv_v2_config still exists %q", rs.Primary.ID)
		}
	}
	return nil
}
