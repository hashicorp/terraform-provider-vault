// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/mfa"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestIdentityMFADuo(t *testing.T) {
	var p *schema.Provider
	t.Parallel()

	resourceName := mfa.ResourceNameDuo + ".test"

	checksCommon := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldName, ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldMountAccessor, ""),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldUUID),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldMethodID),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, mfa.MethodTypeDuo),
		resource.TestCheckResourceAttr(resourceName, consts.FieldNamespaceID, "root"),
	}

	importTestStep := testutil.GetImportTestStep(resourceName, false, nil, consts.FieldIntegrationKey, consts.FieldSecretKey)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
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
  username_format = ""
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
