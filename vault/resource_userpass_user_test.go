// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccUserpassUser_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("userpass")
	resName := "vault_userpass_user.user"
	username := "john_doe"
	password := "supersecretpassword"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccUserpassUserCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassUserConfig_basic(backend, username, password, []string{"admin", "security"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resName, "id", "auth/"+backend+"/users/"+username),
					resource.TestCheckResourceAttr(resName, "backend", backend),
					resource.TestCheckResourceAttr(resName, "username", username),
					resource.TestCheckResourceAttr(resName, "password", password),
					resource.TestCheckResourceAttr(resName, "token_policies.#", "2"),
					resource.TestCheckResourceAttr(resName, "token_policies.0", "admin"),
					resource.TestCheckResourceAttr(resName, "token_policies.1", "security"),
				),
			},
			{
				Config: testAccUserpassUserConfig_basic(backend, username, password, []string{"updated_policy"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resName, "id", "auth/"+backend+"/users/"+username),
					resource.TestCheckResourceAttr(resName, "backend", backend),
					resource.TestCheckResourceAttr(resName, "username", username),
					resource.TestCheckResourceAttr(resName, "password", password),
					resource.TestCheckResourceAttr(resName, "token_policies.#", "1"),
					resource.TestCheckResourceAttr(resName, "token_policies.0", "updated_policy"),
				),
			},
		},
	})
}

func TestAccUserpassUser_importBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("userpass")
	resName := "vault_userpass_user.user"
	user := "u3er_name"
	password := "pa33_word"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassUserConfig_basic(backend, user, password, []string{"security", "admin"}),
			},
			{
				ResourceName:            resName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func TestAccUserpassHelpers(t *testing.T) {
	t.Run("Test helper functions", func(t *testing.T) {
		expectedPath := "auth/userpass/users/blm_hemu"
		expectedBackend := "userpass"
		expectedUsername := "blm_hemu"

		actualPath := userPath(expectedBackend, expectedUsername)
		actualBackend := backendFromPath(expectedPath)
		actualUsername := usernameFromPath(expectedPath)

		if actualPath != expectedPath {
			t.Fatalf("expected path '%s', got: '%s'", expectedPath, actualPath)
		}

		if actualBackend != expectedBackend {
			t.Fatalf("expected backend '%s', got: '%s'", expectedBackend, actualBackend)
		}

		if actualUsername != expectedUsername {
			t.Fatalf("expected username '%s', got: '%s'", expectedUsername, actualUsername)
		}
	})
}

func testAccUserpassUserCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_userpass_user" {
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
	return fmt.Errorf("Userpass user resource still exists")
}

func testAccUserpassUserConfig_basic(backend string, username string, password string, policies []string) string {
	p, _ := json.Marshal(policies)
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
	type = "userpass"
	path = "%s"
}

resource "vault_userpass_user" "user" {
	backend = vault_auth_backend.userpass.path
	username = "%s"
	password = "%s"
	token_policies = %s
}
`, backend, username, password, p)
}
