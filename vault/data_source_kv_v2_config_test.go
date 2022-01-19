package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKvV2ConfigDataSource_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("kv-test")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKvV2ConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKvV2Config_basic(backend, 4),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(4)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", false)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"delete_version_after", "0s"),
				),
			},
			{
				Config: testAccKvV2ConfigDataSource_basic(backend, 4),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("data.vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(4)),
					resource.TestCheckResourceAttr("data.vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", false)),
					resource.TestCheckResourceAttr("data.vault_kv_v2_config.kv-config",
						"delete_version_after", "0s"),
				),
			},
		},
	})
}

func TestAccKvV2ConfigDataSource_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("kv-test")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckKvV2ConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKvV2Config_full(backend, 2, true, "1h5m3s"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(2)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", true)),
					resource.TestCheckResourceAttr("vault_kv_v2_config.kv-config",
						"delete_version_after", "1h5m3s"),
				),
			},
			{
				Config: testAccKvV2ConfigDataSource_full(backend, 2, true, "1h5m3s"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_kv_v2_config.kv-config",
						"path", backend),
					resource.TestCheckResourceAttr("data.vault_kv_v2_config.kv-config",
						"max_versions", fmt.Sprint(2)),
					resource.TestCheckResourceAttr("data.vault_kv_v2_config.kv-config",
						"cas_required", fmt.Sprintf("%t", true)),
					resource.TestCheckResourceAttr("data.vault_kv_v2_config.kv-config",
						"delete_version_after", "1h5m3s"),
				),
			},
		},
	})
}

func testAccKvV2ConfigDataSource_basic(path string, max_versions int) string {
	return fmt.Sprintf(`
%s

data "vault_kv_v2_config" "kv-config" {
  path = %q
}`, testAccKvV2Config_basic(path, max_versions), path)
}

func testAccKvV2ConfigDataSource_full(path string, max_versions int, cas_required bool, delete_version_after string) string {
	return fmt.Sprintf(`
%s

data "vault_kv_v2_config" "kv-config" {
  path = %q
}`, testAccKvV2Config_full(path, max_versions, cas_required, delete_version_after), path)
}
