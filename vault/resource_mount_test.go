package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestZeroTTLDoesNotCauseUpdate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: `
				resource "vault_mount" "zero_ttl" {
					path = "example"
					type = "generic"
				}
				`,
			},
			{
				PlanOnly: true,
				Config: `
				resource "vault_mount" "zero_ttl" {
					path = "example"
					type = "generic"
				}
				`,
			},
		},
	})
}

func TestResourceMount(t *testing.T) {
	path := "example-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_initialConfig(path),
				Check:  testResourceMount_initialCheck(path),
			},
			{
				Config: testResourceMount_updateConfig,
				Check:  testResourceMount_updateCheck,
			},
		},
	})
}

func testResourceMount_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "generic"
	description = "Example mount for testing"
	default_lease_ttl_seconds = 3600
	max_lease_ttl_seconds = 36000
}
`, path)
}

func testResourceMount_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_mount.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id %q doesn't match path %q", path, instanceState.Attributes["path"])
		}

		if path != expectedPath {
			return fmt.Errorf("unexpected path %q, expected %q", path, expectedPath)
		}

		mount, err := findMount(path)
		if err != nil {
			return fmt.Errorf("error reading back mount %q: %s", path, err)
		}

		if wanted := "Example mount for testing"; mount.Description != wanted {
			return fmt.Errorf("description is %v; wanted %v", mount.Description, wanted)
		}

		if wanted := "generic"; mount.Type != wanted {
			return fmt.Errorf("type is %v; wanted %v", mount.Description, wanted)
		}

		if wanted := 3600; mount.Config.DefaultLeaseTTL != wanted {
			return fmt.Errorf("default lease ttl is %v; wanted %v", mount.Description, wanted)
		}

		if wanted := 36000; mount.Config.MaxLeaseTTL != wanted {
			return fmt.Errorf("max lease ttl is %v; wanted %v", mount.Description, wanted)
		}

		return nil
	}
}

var testResourceMount_updateConfig = `

resource "vault_mount" "test" {
	path = "remountingExample"
	type = "generic"
	description = "Example mount for testing"
	default_lease_ttl_seconds = 7200
	max_lease_ttl_seconds = 72000
}

`

func testResourceMount_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_mount.test"]
	instanceState := resourceState.Primary

	path := instanceState.ID

	if path != instanceState.Attributes["path"] {
		return fmt.Errorf("id doesn't match path")
	}

	if path != "remountingExample" {
		return fmt.Errorf("unexpected path value")
	}

	mount, err := findMount(path)
	if err != nil {
		return fmt.Errorf("error reading back mount: %s", err)
	}

	if wanted := "Example mount for testing"; mount.Description != wanted {
		return fmt.Errorf("description is %v; wanted %v", mount.Description, wanted)
	}

	if wanted := "generic"; mount.Type != wanted {
		return fmt.Errorf("type is %v; wanted %v", mount.Description, wanted)
	}

	if wanted := 7200; mount.Config.DefaultLeaseTTL != wanted {
		return fmt.Errorf("default lease ttl is %v; wanted %v", mount.Description, wanted)
	}

	if wanted := 72000; mount.Config.MaxLeaseTTL != wanted {
		return fmt.Errorf("max lease ttl is %v; wanted %v", mount.Description, wanted)
	}

	return nil
}

func findMount(path string) (*api.MountOutput, error) {
	client := testProvider.Meta().(*api.Client)

	path = path + "/"

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, err
	}

	if mounts[path] != nil {
		return mounts[path], nil
	}

	return nil, fmt.Errorf("unable to find mount %s in Vault; current list: %v", path, mounts)
}
