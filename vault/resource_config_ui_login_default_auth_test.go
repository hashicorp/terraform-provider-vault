package vault

import (
	"context"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func testConfigUILoginDefaultAuthConfig(isUpdate bool) string {
	if !isUpdate {
		return `
resource "vault_config_ui_default_auth" "test" {
	name = "test_rule"
	namespace_path = "test"
	default_auth_type = "oidc"
	backup_auth_types = [
		"ldap",
		"userpass",
	]
	disable_inheritance = false
}
`
	} else {
		return `
resource "vault_config_ui_default_auth" "test" {
	name = "test_rule"
	namespace_path = "different_test"
	default_auth_type = "ldap"
	backup_auth_types = [
		"github",
		"saml",
	]
	disable_inheritance = true
}`
	}
}

func TestConfigUILoginDefaultAuth(t *testing.T) {
	t.Parallel()
	//testutil.SkipTestAcc(t)

	resourceType := "vault_config_ui_default_auth"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion120)
		},
		Steps: []resource.TestStep{
			{
				Config: testConfigUILoginDefaultAuthConfig(false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "test_rule"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespacePath, "test/"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, "oidc"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableInheritance, "false"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldDefaultAuthType),
				),
			},
			{
				Config: testConfigUILoginDefaultAuthConfig(true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "test_rule"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespacePath, "different_test/"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, "ldap"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableInheritance, "true"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldDefaultAuthType),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
