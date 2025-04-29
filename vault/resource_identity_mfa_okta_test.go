// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/mfa"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestIdentityMFAOKTA(t *testing.T) {
	var p *schema.Provider
	t.Parallel()

	resourceName := mfa.ResourceNameOKTA + ".test"

	checksCommon := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldName, ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldMountAccessor, ""),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldUUID),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldMethodID),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, mfa.MethodTypeOKTA),
		resource.TestCheckResourceAttr(resourceName, consts.FieldNamespaceID, "root"),
	}

	// FieldPrimaryEmail is not being returned from the API, so we have to ignore it for now.
	importTestStep := testutil.GetImportTestStep(resourceName, false, nil,
		consts.FieldAPIToken,
		consts.FieldPrimaryEmail,
	)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  org_name        = "org1"
  api_token       = "token1"
  base_url        = "qux.baz.com"
  username_format = "{}"
  primary_email   = true
}
`, mfa.ResourceNameOKTA),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldOrgName, "org1"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldAPIToken, "token1"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldBaseURL, "qux.baz.com"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameFormat, "{}"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldPrimaryEmail, "true"),
					)...,
				),
			},
			importTestStep,
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  org_name        = "org2"
  api_token       = "token2"
  base_url        = "foo.baz.com"
  username_format = ""
  primary_email   = false
}
`, mfa.ResourceNameOKTA),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldOrgName, "org2"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldAPIToken, "token2"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldBaseURL, "foo.baz.com"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameFormat, ""),
						resource.TestCheckResourceAttr(resourceName, consts.FieldPrimaryEmail, "false"),
					)...,
				),
			},
			importTestStep,
		},
	})
}
