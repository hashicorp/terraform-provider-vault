package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceConsul_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	accessor := "592fca4f-3ce9-4a00-8730-9a2fac6afabd"
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceConsul_initialConfig(path, token, accessor),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_consul_access_credential.test", "path", path),
					resource.TestCheckResourceAttr("data.vault_consul_access_credential.test", "token", token),
					resource.TestCheckResourceAttr("data.vault_consul_access_credential.test", "accessor", accessor),
				),
			},
		},
	})
}

func testAccDataSourceConsul_initialConfig(path, token, accessor string) string {
	return fmt.Sprintf(`
data "vault_consul_access_credential" "test" {
  path = "%s"
  token = "%s"
  accessor = "%s"
}`, path, token, accessor)
}
