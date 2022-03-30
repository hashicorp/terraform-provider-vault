package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFAOktaBasic(t *testing.T) {
	mfaOktaPath := acctest.RandomWithPrefix("mfa-okta")
	resourceName := "vault_mfa_okta.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestEntPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testMFAOktaConfig(mfaOktaPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", mfaOktaPath),
					resource.TestCheckResourceAttr(resourceName, "username_format", "user@example.com"),
					resource.TestCheckResourceAttr(resourceName, "org_name", "hashicorp"),
				),
			},
		},
	})
}

func testMFAOktaConfig(path string) string {
	userPassPath := acctest.RandomWithPrefix("userpass")

	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_mfa_okta" "test" {
  name                  = %q
  mount_accessor        = vault_auth_backend.userpass.accessor
  username_format       = "user@example.com"
  org_name				= "hashicorp"
  api_token				= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
}
`, userPassPath, path)
}
