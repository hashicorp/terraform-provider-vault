package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourcePolicy(t *testing.T) {
	name := acctest.RandomWithPrefix("test-")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourcePolicy_initialConfig(name),
				Check:  testResourcePolicy_initialCheck(name),
			},
			{
				Config: testResourcePolicy_updateConfig,
				Check:  testResourcePolicy_updateCheck,
			},
		},
	})
}

func testResourcePolicy_initialConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
	name = "%s"
	policy = <<EOT
path "secret/*" {
	policy = "read"
}
EOT
}
`, name)
}

func testResourcePolicy_initialCheck(expectedName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_policy.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		name := instanceState.ID

		if name != instanceState.Attributes["name"] {
			return fmt.Errorf("id %q doesn't match name %q", name, instanceState.Attributes["name"])
		}

		if name != expectedName {
			return fmt.Errorf("unexpected policy name %q, expected %q", name, expectedName)
		}

		client := testProvider.Meta().(*api.Client)
		policy, err := client.Sys().GetPolicy(name)
		if err != nil {
			return fmt.Errorf("error reading back policy: %s", err)
		}

		if got, want := policy, "path \"secret/*\" {\n\tpolicy = \"read\"\n}\n"; got != want {
			return fmt.Errorf("policy data is %q; want %q", got, want)
		}

		return nil
	}
}

var testResourcePolicy_updateConfig = `

resource "vault_policy" "test" {
	name = "dev-team"
	policy = <<EOT
path "secret/*" {
	policy = "write"
}
EOT
}

`

func testResourcePolicy_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_policy.test"]
	instanceState := resourceState.Primary

	name := instanceState.ID

	client := testProvider.Meta().(*api.Client)

	if name != instanceState.Attributes["name"] {
		return fmt.Errorf("id doesn't match name")
	}

	if name != "dev-team" {
		return fmt.Errorf("unexpected policy name")
	}

	policy, err := client.Sys().GetPolicy(name)
	if err != nil {
		return fmt.Errorf("error reading back policy: %s", err)
	}

	if got, want := policy, "path \"secret/*\" {\n\tpolicy = \"write\"\n}\n"; got != want {
		return fmt.Errorf("policy data is %q; want %q", got, want)
	}

	return nil
}
