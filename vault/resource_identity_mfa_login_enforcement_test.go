package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/mfa"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestIdentityMFALoginEnforcement(t *testing.T) {
	t.Parallel()

	name := acctest.RandomWithPrefix("ident-mfa-enf")
	resourceName := mfa.ResourceNameLoginEnforcement + ".test"
	checksCommon := []resource.TestCheckFunc{
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldUUID),
		resource.TestCheckResourceAttr(resourceName, consts.FieldNamespaceID, "root"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
	}

	importTestStep := testutil.GetImportTestStep(resourceName, false, nil, consts.FieldIntegrationKey, consts.FieldSecretKey)
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: getTestMFAEnforcementConfig(name),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon)...,
				),
			},
			importTestStep,
		},
	})
}

func getTestMFAEnforcementConfig(name string) string {
	config := fmt.Sprintf(`
resource "vault_identity_mfa_duo" "test" {
  secret_key      = "secret-key"
  integration_key = "int-key"
  api_hostname    = "foo.baz"
  push_info       = "push-info"
  username_format = "{}"
}

resource "vault_identity_mfa_login_enforcement" "test" {
  name = "%s"
  mfa_method_ids = [
    vault_identity_mfa_duo.test.method_id,
  ]
}
`, name)

	return config
}
