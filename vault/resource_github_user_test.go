package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccGithubUser_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_user.user"
	user := "john_doe"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccGithubUserCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubUserConfig_basic(backend, user, []string{"admin", "security"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resName, "id", "auth/"+backend+"/map/users/"+user),
					resource.TestCheckResourceAttr(resName, "backend", backend),
					resource.TestCheckResourceAttr(resName, "user", "john_doe"),
					resource.TestCheckResourceAttr(resName, "policies.#", "2"),
					resource.TestCheckResourceAttr(resName, "policies.0", "admin"),
					resource.TestCheckResourceAttr(resName, "policies.1", "security"),
				),
			},
			{
				Config: testAccGithubUserConfig_basic(backend, user, []string{}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resName, "id", "auth/"+backend+"/map/users/"+user),
					resource.TestCheckResourceAttr(resName, "backend", backend),
					resource.TestCheckResourceAttr(resName, "user", "john_doe"),
					resource.TestCheckResourceAttr(resName, "policies.#", "0"),
				),
			},
		},
	})
}

func TestAccGithubUser_importBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_user.user"
	user := "import"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubUserConfig_basic(backend, user, []string{"security", "admin"}),
			},
			{
				ResourceName:      resName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestGithubUserBackEndPath(t *testing.T) {
	t.Run("With default mount", func(t *testing.T) {
		actual := githubMappingPath("auth/github/map/users/foo", "users")
		if actual != "github" {
			t.Fatalf("expected '%s', got: '%s'", "github", actual)
		}
	})
	t.Run("With custom mount", func(t *testing.T) {
		actual := githubMappingPath("auth/mymount/submount/map/users/foo", "users")
		if actual != "mymount/submount" {
			t.Fatalf("expected '%s', got: '%s'", "mymount/submount", actual)
		}
	})
}

func testAccGithubUserCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)
	for _, r := range s.RootModule().Resources {
		if r.Type != "vault_github_user" {
			continue
		}

		resp, err := client.RawRequest(client.NewRequest("GET", "/v1/"+r.Primary.ID))
		log.Printf("[DEBUG] Checking if resource '%s' is destroyed, statusCode: %d, error: %s", r.Primary.ID, resp.StatusCode, err)
		if resp.StatusCode == 404 {
			return nil
		}
	}
	return fmt.Errorf("Github user resource still exists")
}

func testAccGithubUserConfig_basic(backend string, user string, policies []string) string {
	p, _ := json.Marshal(policies)
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
	path = "%s"
  	organization = "vault"
}

resource "vault_github_user" "user" {
	backend = "${vault_github_auth_backend.gh.id}"
	user = "%s"
	policies = %s
}
`, backend, user, p)
}
