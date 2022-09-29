package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/mfa"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestIdentityLoginMFADuo(t *testing.T) {
	resourceName := mfa.ResourceNameDuo + ".test"

	checksCommon := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, mfa.MethodTypeDuo),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldUUID),
		resource.TestCheckResourceAttr(resourceName, consts.FieldNamespaceID, "root"),
	}

	for k := range mfa.GetDuoSchemaResource().Schema {
		switch k {
		case consts.FieldName, consts.FieldMountAccessor:
			checksCommon = append(checksCommon, resource.TestCheckResourceAttr(resourceName, k, ""))
		}
	}

	importTestStep := testutil.GetImportTestStep(resourceName, false, nil, consts.FieldIntegrationKey, consts.FieldSecretKey)
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  secret_key      = "secret-key"
  integration_key = "int-key"
  api_hostname    = "foo.baz"
  push_info       = "push-info"
  username_format = "{}"
}
`, mfa.ResourceNameDuo),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, "secret-key"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldIntegrationKey, "int-key"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldAPIHostname, "foo.baz"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldPushInfo, "push-info"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameFormat, "{}"),
					)...,
				),
			},
			importTestStep,
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  secret_key      = "secret-key-2"
  integration_key = "int-key-2"
  api_hostname    = "foo.baz"
  push_info       = "push-info-2"
}
`, mfa.ResourceNameDuo),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, "secret-key-2"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldIntegrationKey, "int-key-2"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldAPIHostname, "foo.baz"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldPushInfo, "push-info-2"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameFormat, ""),
					)...,
				),
			},
			importTestStep,
		},
	})
}
