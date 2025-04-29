// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/mfa"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestIdentityMFAPingID(t *testing.T) {
	var p *schema.Provider
	t.Parallel()

	pingIDConfigTmpl := `
use_base64_key=bXktc2VjcmV0LWtleQ==
use_signature=%t
token=token1
idp_url=https://idpxnyl3m.pingidentity.com/pingid
org_alias=%s
admin_url=https://idpxnyl3m.pingidentity.com/pingid
authenticator_url=https://authenticator.pingone.com/pingid/ppm
`
	pingIDConfigCreate := fmt.Sprintf(pingIDConfigTmpl, false, "org-alias1")
	pingIDConfigCreateB64 := base64.StdEncoding.EncodeToString([]byte(pingIDConfigCreate))

	pingIDConfigUpdate := fmt.Sprintf(pingIDConfigTmpl, true, "org-alias2")
	pingIDConfigUpdateB64 := base64.StdEncoding.EncodeToString([]byte(pingIDConfigUpdate))

	resourceName := mfa.ResourceNamePingID + ".test"
	checksCommon := []resource.TestCheckFunc{
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldUUID),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldMethodID),
		resource.TestCheckResourceAttr(resourceName, consts.FieldNamespaceID, "root"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldIdpURL, "https://idpxnyl3m.pingidentity.com/pingid"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAdminURL, "https://idpxnyl3m.pingidentity.com/pingid"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAuthenticatorURL, "https://authenticator.pingone.com/pingid/ppm"),
	}

	importTestStep := testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSettingsFileBase64)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  settings_file_base64 = "%s"
}
`, mfa.ResourceNamePingID, pingIDConfigCreateB64),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldUseSignature, "false"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOrgAlias, "org-alias1"),
					)...,
				),
			},
			importTestStep,
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  settings_file_base64 = "%s"
}
`, mfa.ResourceNamePingID, pingIDConfigUpdateB64),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldUseSignature, "true"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldOrgAlias, "org-alias2"),
					)...,
				),
			},
			importTestStep,
		},
	})
}
