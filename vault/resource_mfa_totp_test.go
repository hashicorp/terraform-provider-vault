package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFATOTPBasic(t *testing.T) {
	mfaTOTPPath := acctest.RandomWithPrefix("mfa-totp")
	resourceName := "vault_mfa_totp.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestEntPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testMFATOTPConfig(mfaTOTPPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", mfaTOTPPath),
					resource.TestCheckResourceAttr(resourceName, "issuer", "hashicorp"),
					resource.TestCheckResourceAttr(resourceName, "period", "60"),
					resource.TestCheckResourceAttr(resourceName, "algorithm", "SHA256"),
					resource.TestCheckResourceAttr(resourceName, "digits", "8"),
				),
			},
		},
	})
}

func testMFATOTPConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mfa_totp" "test" {
  name                  = %q
  issuer        		= "hashicorp"	 
  period       			= 60
  algorithm				= "SHA256"
  digits				= 8
}
`, path)
}
