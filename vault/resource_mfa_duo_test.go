// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFADuoBasic(t *testing.T) {
	mfaDuoPath := acctest.RandomWithPrefix("mfa-duo")

	resourceName := "vault_mfa_duo.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testMFADuoConfig(mfaDuoPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", mfaDuoPath),
					resource.TestCheckResourceAttr(resourceName, "secret_key", "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"),
					resource.TestCheckResourceAttr(resourceName, "integration_key", "BIACEUEAXI20BNWTEYXT"),
					resource.TestCheckResourceAttr(resourceName, "api_hostname", "api-2b5c39f5.duosecurity.com"),
					resource.TestCheckResourceAttr(resourceName, "username_format", "user@example.com"),
					resource.TestCheckResourceAttr(resourceName, "push_info", "from=loginortal&domain=example.com"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"name",
				"secret_key",
				"integration_key"),
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
