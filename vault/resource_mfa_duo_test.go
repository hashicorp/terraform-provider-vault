package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFADuoBasic(t *testing.T) {
	mfaDuoPath := acctest.RandomWithPrefix("mfa-duo")

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestEntPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testMFADuoConfig(mfaDuoPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "name", mfaDuoPath),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "secret_key", "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "integration_key", "BIACEUEAXI20BNWTEYXT"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "api_hostname", "api-2b5c39f5.duosecurity.com"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "username_format", "user@example.com"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "push_info", "from=loginortal&domain=example.com"),
				),
			},
		},
	})
}

func testMFADuoConfig(path string) string {
	userPassPath := acctest.RandomWithPrefix("userpass")

	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_mfa_duo" "test" {
  name                  = %q
  mount_accessor        = vault_auth_backend.userpass.accessor
  secret_key            = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
  integration_key       = "BIACEUEAXI20BNWTEYXT"
  api_hostname          = "api-2b5c39f5.duosecurity.com"
  username_format       = "user@example.com"
  push_info             = "from=loginortal&domain=example.com"
}
`, userPassPath, path)
}
