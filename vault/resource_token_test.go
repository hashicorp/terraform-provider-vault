package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestResourceToken(t *testing.T) {
	policy := acctest.RandomWithPrefix("test-")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testResourceToken_initialConfig(),
				Check:  testResourceToken_initialCheck(),
			},
			resource.TestStep{
				Config: testResourceToken_policyConfig(policy),
				Check:  testResourceToken_policyCheck(policy),
			},
		},
	})
}

func testResourceToken_initialConfig() string {
	return `
resource "vault_token" "test" {
	policies = [ "basic" ]
}
`
}

func testResourceToken_initialCheck() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_token.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		name := instanceState.ID

		if name != instanceState.Attributes["client_token"] {
			return fmt.Errorf("id %q doesn't match client_token %q", name, instanceState.Attributes["client_token"])
		}

		return nil
	}
}

func testResourceToken_policyConfig(policy string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
	name = "%s"
	policy = <<EOT
path "secret/*" {
	policy = "read"
}
EOT
}

resource "vault_token" "test" {
	policies = [ "${vault_policy.test.name}" ]
}
`, policy)
}

func testResourceToken_policyCheck(expectedPolicy string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_token.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		policiesCount := instanceState.Attributes["policies.#"]
		if policiesCount != "1" {
			return fmt.Errorf("unexpected policies count %s, expected %d", policiesCount, 1)
		}

		policy := instanceState.Attributes["policies.0"]
		if policy != expectedPolicy {
			return fmt.Errorf("unexpected policy name %q, expected %q", policy, expectedPolicy)
		}

		return nil
	}
}
