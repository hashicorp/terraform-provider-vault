// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccGithubUser_basic(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_user.user"
	user := "john_doe"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccGithubUserCheckDestroy,
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_user.user"
	user := "import"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
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
	var p *schema.Provider
	t.Run("With default mount", func(t *testing.T) {
		var p *schema.Provider
		actual := githubMappingPath("auth/github/map/users/foo", "users")
		if actual != "github" {
			t.Fatalf("expected '%s', got: '%s'", "github", actual)
		}
	})
	t.Run("With custom mount", func(t *testing.T) {
		var p *schema.Provider
		actual := githubMappingPath("auth/mymount/submount/map/users/foo", "users")
		if actual != "mymount/submount" {
			t.Fatalf("expected '%s', got: '%s'", "mymount/submount", actual)
		}
	})
}

func testAccGithubUserCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_github_user" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		resp, err := client.RawRequest(client.NewRequest("GET", "/v1/"+rs.Primary.ID))
		log.Printf("[DEBUG] Checking if resource '%s' is destroyed, statusCode: %d, error: %s", rs.Primary.ID, resp.StatusCode, err)
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
	organization = "hashicorp"
}

resource "vault_github_user" "user" {
	backend = vault_github_auth_backend.gh.id
	user = "%s"
	policies = %s
}
`, backend, user, p)
}
