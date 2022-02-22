package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

var testVar = "{\"groups\": {{identity.entity.groups.names}} }"

func TestAccIdentityOIDCScope(t *testing.T) {
	name := acctest.RandomWithPrefix("test-scope")
	resourceName := "vault_identity_oidc_scope.test"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOIDCSCopeConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "test scope"),
					resource.TestCheckResourceAttr(resourceName, "template", testVar),
				),
			},
			{
				Config: testAccIdentityOIDCSCopeConfig_update(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "test scope updated description"),
					resource.TestCheckResourceAttr(resourceName, "template", testVar),
				),
			},
		},
	})
}

func testAccIdentityOIDCSCopeConfig_basic(scope string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_scope" "test" {
  name        = "%s"
  template    = "{\"groups\": {{identity.entity.groups.names}} }"
  description = "test scope"
}`, scope)
}

func testAccIdentityOIDCSCopeConfig_update(scope string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_scope" "test" {
  name        = "%s"
  template    = "{\"groups\": {{identity.entity.groups.names}} }"
  description = "test scope updated description"
}`, scope)
}
