package vault

import (
	"fmt"
	"testing"

	r "github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

// Prerequisite - `vault secret enable consul`
// need to establish and enable consul secret backend before running this test.

func TestResourceConsulSecretRole(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []r.TestStep{
			r.TestStep{
				Config: testResourceConsulSecretRole_config,
				Check:  testResourceConsulSecretRole_check,
			},
		},
	})
}

var testResourceConsulSecretRole_config = `

resource "vault_consul_secret_backend_role" "test" {
  mount = "consul"
  name = "test"
  role = <<EOF
key "lolly" { policy = "read" }
key "pop" { policy = "write" }
EOF
}

`

func testResourceConsulSecretRole_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_consul_secret_backend_role.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	return nil
}
