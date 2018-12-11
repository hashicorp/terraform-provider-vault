package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceAuth(t *testing.T) {
	path := "github-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceAuth_initialConfig(path),
				Check:  testResourceAuth_initialCheck(path),
			},
			{
				Config: testResourceAuth_updateConfig,
				Check:  testResourceAuth_updateCheck,
			},
		},
	})
}

func testAccCheckAuthBackendDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		return err
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_auth_backend" {
			continue
		}
		instanceState := rs.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		if _, ok := auths[instanceState.ID]; ok {
			return fmt.Errorf("Auth backend still exists")
		}
	}
	return nil
}

func testResourceAuth_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "github"
	path = "%s"
	description = "Test auth backend"
	default_lease_ttl_seconds = 3600
	max_lease_ttl_seconds = 86400
	listing_visibility = "unauth"
	local = true
}`, path)
}

func testResourceAuth_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_auth_backend.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path+"/" != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}

		if path != expectedPath {
			return fmt.Errorf("unexpected auth path %q, expected %q", path, expectedPath)
		}

		if instanceState.Attributes["type"] != "github" {
			return fmt.Errorf("unexpected auth type")
		}

		if instanceState.Attributes["description"] != "Test auth backend" {
			return fmt.Errorf("unexpected auth description")
		}

		if instanceState.Attributes["default_lease_ttl_seconds"] != "3600" {
			return fmt.Errorf("unexpected auth default_lease_ttl_seconds")
		}

		if instanceState.Attributes["max_lease_ttl_seconds"] != "86400" {
			return fmt.Errorf("unexpected auth max_lease_ttl_seconds")
		}

		if instanceState.Attributes["listing_visibility"] != "unauth" {
			return fmt.Errorf("unexpected auth listing_visibility")
		}

		if instanceState.Attributes["local"] != "true" {
			return fmt.Errorf("unexpected auth local")
		}

		client := testProvider.Meta().(*api.Client)
		auths, err := client.Sys().ListAuth()

		if err != nil {
			return fmt.Errorf("error reading back auth: %s", err)
		}

		found := false
		for serverPath, serverAuth := range auths {
			if serverPath == expectedPath+"/" {
				found = true
				if serverAuth.Type != "github" {
					return fmt.Errorf("unexpected auth type")
				}
				if serverAuth.Description != "Test auth backend" {
					return fmt.Errorf("unexpected auth description")
				}
				if serverAuth.Config.DefaultLeaseTTL != 3600 {
					return fmt.Errorf("unexpected auth default_lease_ttl_seconds")
				}
				if serverAuth.Config.MaxLeaseTTL != 86400 {
					return fmt.Errorf("unexpected auth max_lease_ttl_seconds")
				}
				if serverAuth.Config.ListingVisibility != "unauth" {
					return fmt.Errorf("unexpected auth listing_visibility")
				}
				if serverAuth.Local != true {
					return fmt.Errorf("unexpected auth local")
				}
				break
			}
		}

		if !found {
			return fmt.Errorf("could not find auth backend %q in %+v", expectedPath, auths)
		}

		return nil
	}
}

var testResourceAuth_updateConfig = `

resource "vault_auth_backend" "test" {
	type = "ldap"
}

`

func testResourceAuth_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_auth_backend.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	name := instanceState.ID

	if name != instanceState.Attributes["type"] {
		return fmt.Errorf("id doesn't match name")
	}

	if name != "ldap" {
		return fmt.Errorf("unexpected auth name")
	}

	client := testProvider.Meta().(*api.Client)
	auths, err := client.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error reading back auth: %s", err)
	}

	found := false
	for _, auth := range auths {
		if auth.Type == name {
			found = true
			if wanted := instanceState.Attributes["accessor"]; auth.Accessor != wanted {
				return fmt.Errorf("accessor is %v; wanted %v", auth.Accessor, wanted)
			}
			break
		}
	}

	if !found {
		return fmt.Errorf("could not find auth backend %s in %+v", name, auths)
	}

	return nil
}
