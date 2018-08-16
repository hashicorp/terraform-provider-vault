package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceGithubTeamMap(t *testing.T) {
	name := acctest.RandomWithPrefix("test-")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testResourceGithubTeamMap_initialConfig(name),
				Check:  testResourceGithubTeamMap_initialCheck(name),
			},
			resource.TestStep{
				Config: testResourceGithubTeamMap_updateConfig,
				Check:  testResourceGithubTeamMap_updateCheck,
			},
		},
	})
}

func testResourceGithubTeamMap_initialConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_github_team_map" "test" {
	name = "%s"
	policies = "example"
}
`, name)
}

func testResourceGithubTeamMap_initialCheck(expectedName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_github_team_map.test"]
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
		policies, err := client.Sys().GetGithubTeamMap(name)
		if err != nil {
			return fmt.Errorf("error reading back policy: %s", err)
		}

		if got, want := policies, "path \"secret/*\" {\n\tpolicy = \"read\"\n}\n"; got != want {
			return fmt.Errorf("policy data is %q; want %q", got, want)
		}

		return nil
	}
}

var testResourceGithubTeamMap_updateConfig = `

resource "vault_github_team_map" "test" {
	name = "test"
	policies = "example"
}
`

func testResourceGithubTeamMap_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_github_team_map.test"]
	instanceState := resourceState.Primary

	name := instanceState.ID

	client := testProvider.Meta().(*api.Client)

	if name != instanceState.Attributes["name"] {
		return fmt.Errorf("id doesn't match name")
	}

	if name != "dev-team" {
		return fmt.Errorf("unexpected policy name")
	}

	policies, err := client.Sys().GetGithubTeamMap(name)
	if err != nil {
		return fmt.Errorf("error reading back policy: %s", err)
	}

	if got, want := policies, "dev-team"; got != want {
		return fmt.Errorf("policy data is %q; want %q", got, want)
	}

	return nil
}
