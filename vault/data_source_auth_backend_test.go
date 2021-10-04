package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataSourceAuthBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("foo")
	r.Test(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []r.TestStep{
			{
				Config: testDataSourceAuthBackendBasic_config,
				Check:  testDataSourceAuthBackend_check,
			},
			{
				Config: testDataSourceAuthBackend_config(path),
				Check:  testDataSourceAuthBackend_check,
			},
		},
	})
}

var testDataSourceAuthBackendBasic_config = `

resource "vault_auth_backend" "test" {
	type = "userpass"
}

data "vault_auth_backend" "test" {
	path = vault_auth_backend.test.path
}

`

func testDataSourceAuthBackend_config(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	path = "%s"
	type = "userpass"
}

data "vault_auth_backend" "test" {
	path = vault_auth_backend.test.path
}
`, path)
}

func testDataSourceAuthBackend_check(s *terraform.State) error {
	baseResourceState := s.Modules[0].Resources["vault_auth_backend.test"]
	if baseResourceState == nil {
		return fmt.Errorf("base resource not found in state %v", s.Modules[0].Resources)
	}

	baseInstanceState := baseResourceState.Primary
	if baseInstanceState == nil {
		return fmt.Errorf("base resource has no primary instance")
	}

	resourceState := s.Modules[0].Resources["data.vault_auth_backend.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if got, want := iState.Attributes["id"], baseInstanceState.Attributes["id"]; got != want {
		return fmt.Errorf("id contains %s; want %s", got, want)
	}

	if got, want := iState.Attributes["type"], "userpass"; got != want {
		return fmt.Errorf("type contains %s; want %s", got, want)
	}

	if got, want := iState.Attributes["accessor"], baseInstanceState.Attributes["accessor"]; got != want {
		return fmt.Errorf("accessor contains %s; want %s", got, want)
	}

	return nil
}
