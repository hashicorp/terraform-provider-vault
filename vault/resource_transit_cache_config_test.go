package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccTransitCacheConfig(t *testing.T) {
	name := acctest.RandomWithPrefix("test-cache-config")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccTransitCacheConfigCheckDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccTransitCacheConfig(name, 600),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_cache_config.cfg", "size", "600"),
					testAccTransitCacheConfigCheckApi(600),
				),
			},
			{
				Config: testAccTransitCacheConfig(name, 700),
				Check:  resource.TestCheckResourceAttr("vault_transit_secret_cache_config.cfg", "size", "700"),
			},
			{
				Config: testAccTransitCacheConfig(name, 0),
				Check:  resource.TestCheckResourceAttr("vault_transit_secret_cache_config.cfg", "size", "0"),
			},
			{
				Config: testAccTransitCacheConfigRemoved(name),
				Check:  testAccTransitCacheConfigCheckRemoved,
			},
		},
	})
}

func testAccTransitCacheConfigCheckDestroyed(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transit_secret_cache_config" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for transit cache config %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Transit cache config %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccTransitCacheConfigCheckApi(size int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_transit_secret_cache_config.cfg"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("instance not found in state")
		}

		id := instanceState.ID

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(id)
		if err != nil {
			return err
		}

		sizeStr := strconv.Itoa(size)
		act := resp.Data["size"].(json.Number).String()
		if act != sizeStr {
			return fmt.Errorf("expected side %q, got %q", sizeStr, act)
		}

		return nil
	}
}

func testAccTransitCacheConfigCheckRemoved(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_transit_secret_cache_config.cfg"]
	if resourceState != nil {
		return errors.New("transit cache config still present in state")
	}

	return nil
}

func testAccTransitCacheConfig(entityName string, size int) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_cache_config" "cfg" {
  backend = vault_mount.transit.path
  size    = %d
}`, entityName, size)
}

func testAccTransitCacheConfigRemoved(entityName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}`, entityName)
}
