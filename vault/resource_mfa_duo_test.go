package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFADuoBasic(t *testing.T) {
	mfaDuoConfig := fmt.Sprintf(`
		resource "vault_mfa_duo" "test" {
		secret_key            = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
		integration_key       = "BIACEUEAXI20BNWTEYXT"
		api_hostname          = "api-2b5c39f5.duosecurity.com"
		username_format       = "user@example.com"
		push_info             = "from=loginortal&domain=example.com"
		}
	`)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: mfaDuoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "secret_key", "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "integration_key", "BIACEUEAXI20BNWTEYXT"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "api_hostname", "api-2b5c39f5.duosecurity.com"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "username_format", "user@example.com"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "push_info", "from=loginortal&domain=example.com"),
					resource.TestCheckResourceAttr("vault_mfa_duo.test", "use_passcode", "false"),
				),
			},
		},
	})
}
