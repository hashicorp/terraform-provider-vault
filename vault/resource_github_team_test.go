package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccGithubTeam_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_team.team"
	team := "my-team-slugified"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccGithubTeamCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubTeamConfig_basic(backend, team, []string{"admin", "security"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resName, "id", "auth/"+backend+"/map/teams/"+team),
					resource.TestCheckResourceAttr(resName, "backend", backend),
					resource.TestCheckResourceAttr(resName, "team", "my-team-slugified"),
					resource.TestCheckResourceAttr(resName, "policies.#", "2"),
					resource.TestCheckResourceAttr(resName, "policies.0", "admin"),
					resource.TestCheckResourceAttr(resName, "policies.1", "security"),
				),
			},
			{
				Config: testAccGithubTeamConfig_basic(backend, team, []string{}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resName, "id", "auth/"+backend+"/map/teams/"+team),
					resource.TestCheckResourceAttr(resName, "backend", backend),
					resource.TestCheckResourceAttr(resName, "team", "my-team-slugified"),
					resource.TestCheckResourceAttr(resName, "policies.#", "0"),
				),
			},
		},
	})
}

func TestAccGithubTeam_teamConfigError(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	team := "Team With Spaces"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccGithubTeamCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccGithubTeamConfig_basic(backend, team, []string{}),
				ExpectError: regexp.MustCompile(`\: expected team to be a slugified value*`),
			},
		},
	})
}

func TestAccGithubTeam_importBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_team.team"
	team := "import-team"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubTeamConfig_basic(backend, team, []string{"admin", "developer"}),
			},
			{
				ResourceName:      resName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestGithubTeamBackEndPath(t *testing.T) {
	t.Run("With default mount", func(t *testing.T) {
		actual := githubMappingPath("auth/github/map/teams/foo", "teams")
		if actual != "github" {
			t.Fatalf("expected '%s', got: '%s'", "github", actual)
		}
	})
	t.Run("With custom mount", func(t *testing.T) {
		actual := githubMappingPath("auth/mymount/submount/map/teams/foo", "teams")
		if actual != "mymount/submount" {
			t.Fatalf("expected '%s', got: '%s'", "mymount/submount", actual)
		}
	})
}

func testAccGithubTeamCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*util.Client)
	for _, r := range s.RootModule().Resources {
		if r.Type != "vault_github_team" {
			continue
		}
		req, err := client.NewRequest("GET", "/v1/"+r.Primary.ID)
		if err != nil {
			return fmt.Errorf("error creating new request: %w", err)
		}
		resp, err := client.RawRequest(req)
		log.Printf("[DEBUG] Checking if resource '%s' is destroyed, statusCode: %d, error: %s", r.Primary.ID, resp.StatusCode, err)
		if resp.StatusCode == 404 {
			return nil
		}
	}
	return fmt.Errorf("Github Team resource still exists")
}

func testAccGithubTeamConfig_basic(backend string, team string, policies []string) string {
	p, _ := json.Marshal(policies)
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
	path = "%s"
  	organization = "vault"
}

resource "vault_github_team" "team" {
	backend = "${vault_github_auth_backend.gh.id}"
	team = "%s"
	policies = %s
}
`, backend, team, p)
}
