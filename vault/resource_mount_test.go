package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

type mountConfig struct {
	path      string
	mountType string
	version   string
	seal_wrap bool
}

func TestZeroTTLDoesNotCauseUpdate(t *testing.T) {
	path := acctest.RandomWithPrefix("example")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
				resource "vault_mount" "zero_ttl" {
					path = "%s"
					type = "kv"
				}
				`, path),
			},
			{
				PlanOnly: true,
				Config: fmt.Sprintf(`
				resource "vault_mount" "zero_ttl" {
					path = "%s"
					type = "kv"
				}
				`, path),
			},
		},
	})
}

func TestResourceMount(t *testing.T) {
	path := "example-" + acctest.RandString(10)
	cfg := mountConfig{
		path:      path,
		mountType: "kv",
		version:   "1",
	}
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_initialConfig(cfg),
				Check:  testResourceMount_initialCheck(cfg),
			},
			{
				Config: testResourceMount_updateConfig,
				Check:  testResourceMount_updateCheck,
			},
		},
	})
}

// Test Local flag

func TestResourceMount_Local(t *testing.T) {
	path := "example-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_InitialConfigLocalMount(path),
				Check:  testResourceMount_InitialCheckLocalMount(path),
			},
			{
				Config: testResourceMount_UpdateConfigLocalMount,
				Check:  testResourceMount_UpdateCheckLocalMount,
			},
		},
	})
}

// Test SealWrap flag

func TestResourceMount_SealWrap(t *testing.T) {
	path := "example-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_InitialConfigSealWrap(path),
				Check:  testResourceMount_InitialCheckSealWrap(path),
			},
			{
				Config: testResourceMount_UpdateConfigSealWrap,
				Check:  testResourceMount_UpdateCheckSealWrap,
			},
		},
	})
}

func TestResourceMount_KVV2(t *testing.T) {
	path := acctest.RandomWithPrefix("example")
	kvv2Cfg := fmt.Sprintf(`
			resource "vault_mount" "test" {
				path = "%s"
				type = "kv-v2"
				description = "Example mount for testing"
				default_lease_ttl_seconds = 3600
				max_lease_ttl_seconds = 36000
			}`, path)
	resource.Test(t, resource.TestCase{

		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: kvv2Cfg,

				// Vault will store this and report it back as "kv", version 2
				Check: testResourceMount_initialCheck(mountConfig{
					path:      path,
					mountType: "kv",
					version:   "2",
				}),
			},
			{
				PlanOnly: true,
				Config:   kvv2Cfg,
			},
		},
	})
}

func TestResourceMount_ExternalEntropyAccess(t *testing.T) {
	path := acctest.RandomWithPrefix("example")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_InitialConfigExternalEntropyAccess(path),
				Check:  testResourceMount_CheckExternalEntropyAccess(path, false),
			},
			{
				Config: testResourceMount_UpdateConfigExternalEntropyAccess(path, true),
				Check:  testResourceMount_CheckExternalEntropyAccess(path, true),
			},
			{
				Config: testResourceMount_UpdateConfigExternalEntropyAccess(path, false),
				Check:  testResourceMount_CheckExternalEntropyAccess(path, false),
			},
			{
				Config: testResourceMount_UpdateConfigExternalEntropyAccess(path, true),
				Check:  testResourceMount_CheckExternalEntropyAccess(path, true),
			},
			{
				Config: testResourceMount_InitialConfigExternalEntropyAccess(path),
				Check:  testResourceMount_CheckExternalEntropyAccess(path, false),
			},
		},
	})
}

func testResourceMount_initialConfig(cfg mountConfig) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "%s"
	description = "Example mount for testing"
	default_lease_ttl_seconds = 3600
	max_lease_ttl_seconds = 36000
	options = {
		version = "1"
	}
}
`, cfg.path, cfg.mountType)
}

func testResourceMount_initialCheck(cfg mountConfig) resource.TestCheckFunc {
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

		if path != cfg.path {
			return fmt.Errorf("unexpected path %q, expected %q", path, cfg.path)
		}

		mount, err := findMount(path)
		if err != nil {
			return fmt.Errorf("error reading back mount %q: %s", path, err)
		}

		if wanted := "Example mount for testing"; mount.Description != wanted {
			return fmt.Errorf("description is %v; wanted %v", mount.Description, wanted)
		}

		if wanted := cfg.mountType; mount.Type != wanted {
			return fmt.Errorf("type is %v; wanted %v", mount.Type, wanted)
		}

		if wanted := 3600; mount.Config.DefaultLeaseTTL != wanted {
			return fmt.Errorf("default lease ttl is %v; wanted %v", mount.Config.DefaultLeaseTTL, wanted)
		}

		if wanted := 36000; mount.Config.MaxLeaseTTL != wanted {
			return fmt.Errorf("max lease ttl is %v; wanted %v", mount.Config.MaxLeaseTTL, wanted)
		}

		if wanted := cfg.version; mount.Options["version"] != wanted {
			return fmt.Errorf("version is %v; wanted %v", mount.Options["version"], wanted)
		}

		return nil
	}
}

var testResourceMount_updateConfig = `

resource "vault_mount" "test" {
	path = "remountingExample"
	type = "kv"
	description = "Updated example mount for testing"
	default_lease_ttl_seconds = 7200
	max_lease_ttl_seconds = 72000
	options = {
		version = "1"
	}
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

	if wanted := "Updated example mount for testing"; mount.Description != wanted {
		return fmt.Errorf("description is %v; wanted %v", mount.Description, wanted)
	}

	if wanted := instanceState.Attributes["accessor"]; mount.Accessor != wanted {
		return fmt.Errorf("accessor is %v; wanted %v", mount.Accessor, wanted)
	}

	if wanted := "kv"; mount.Type != wanted {
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

func testResourceMount_InitialConfigLocalMount(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	description = "Example local mount for testing"
	default_lease_ttl_seconds = 3600
	max_lease_ttl_seconds = 36000
	local = true
	options = {
		version = "1"
	}
}
`, path)
}

func testResourceMount_InitialCheckLocalMount(expectedPath string) resource.TestCheckFunc {
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

		if wanted := true; mount.Local != wanted {
			return fmt.Errorf("local is %v; wanted %t", mount.Description, wanted)
		}

		return nil
	}
}

var testResourceMount_UpdateConfigLocalMount = `

resource "vault_mount" "test" {
	path = "remountingExample"
	type = "kv"
	description = "Example mount for testing"
	default_lease_ttl_seconds = 7200
	max_lease_ttl_seconds = 72000
	local = false
	options = {
		version = "1"
	}
}

`

func testResourceMount_UpdateCheckLocalMount(s *terraform.State) error {
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

	if wanted := false; mount.Local != wanted {
		return fmt.Errorf("local is %v; wanted %t", mount.Description, wanted)
	}

	return nil
}

func testResourceMount_InitialConfigSealWrap(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	description = "Example local mount for testing"
	default_lease_ttl_seconds = 3600
	max_lease_ttl_seconds = 36000
	options = {
		version = "1"
	}
	seal_wrap = true
}
`, path)
}

func testResourceMount_InitialCheckSealWrap(expectedPath string) resource.TestCheckFunc {
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

		if wanted := true; mount.SealWrap != wanted {
			return fmt.Errorf("seal_wrap is %v; wanted %t", mount.SealWrap, wanted)
		}

		return nil
	}
}

var testResourceMount_UpdateConfigSealWrap = `

resource "vault_mount" "test" {
	path = "remountingExample"
	type = "kv"
	description = "Example mount for testing"
	default_lease_ttl_seconds = 7200
	max_lease_ttl_seconds = 72000
	options = {
		version = "1"
	}
	seal_wrap = false
}

`

func testResourceMount_UpdateCheckSealWrap(s *terraform.State) error {
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

	if wanted := false; mount.SealWrap != wanted {
		return fmt.Errorf("seal_wrap is %v; wanted %t", mount.SealWrap, wanted)
	}

	return nil
}

func testResourceMount_CheckExternalEntropyAccess(expectedPath string, expectedExternalEntropyAccess bool) resource.TestCheckFunc {
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

		if mount.ExternalEntropyAccess != expectedExternalEntropyAccess {
			return fmt.Errorf("external_entropy_access is %v; wanted %t", mount.ExternalEntropyAccess,
				expectedExternalEntropyAccess)
		}

		return nil
	}
}

func testResourceMount_InitialConfigExternalEntropyAccess(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "transit"
	description = "Example mount for testing"
	default_lease_ttl_seconds = 3600
	max_lease_ttl_seconds = 36000
}
`, path)
}

func testResourceMount_UpdateConfigExternalEntropyAccess(path string, externalEntropyAccess bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "transit"
	description = "Example mount for testing"
	default_lease_ttl_seconds = 3600
	max_lease_ttl_seconds = 36000
	external_entropy_access = %t
}
`, path, externalEntropyAccess)
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
