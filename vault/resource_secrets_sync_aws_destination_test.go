// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	defaultSecretsSyncTemplate = "vault/{{ .MountAccessor }}/{{ .SecretPath }}"
	updatedSecretsSyncTemplate = "VAULT_{{ .MountAccessor | uppercase }}_{{ .SecretPath | uppercase }}"
)

func TestAWSSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws")

	resourceName := "vault_secrets_sync_aws_destination.test"

	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretsSyncDestinationConfig_initial(accessKey, secretKey, region, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "role-arn-test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "external-id-test"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
				),
			},
			{
				Config: testAWSSecretsSyncDestinationConfig_updated(accessKey, secretKey, region, destName, updatedSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, updatedSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "role-arn-test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "external-id-test"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.baz", "bux"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessKeyID,
				fieldSecretAccessKey,
			),
		},
	})
}

func testAWSSecretsSyncDestinationConfig_initial(accessKey, secretKey, region, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                 = "%s"
  access_key_id        = "%s"
  secret_access_key    = "%s"
  region               = "%s"
  role_arn			   = "role-arn-test"
  external_id          = "external-id-test"
  %s
}
`, destName, accessKey, secretKey, region, testSecretsSyncDestinationCommonConfig(templ, false, true, false))

	return ret
}

func testAWSSecretsSyncDestinationConfig_updated(accessKey, secretKey, region, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                 = "%s"
  access_key_id        = "%s"
  secret_access_key    = "%s"
  region               = "%s"
  role_arn			   = "role-arn-updated"
  external_id          = "external-id-updated"
  %s
}
`, destName, accessKey, secretKey, region, testSecretsSyncDestinationCommonConfig(templ, true, true, true))

	return ret
}

func testSecretsSyncDestinationCommonConfig(templ string, withTemplate, withTags, update bool) string {
	ret := ""
	if withTemplate {
		ret += fmt.Sprintf(`
  secret_name_template = "%s"
`, templ)
	}

	if withTags && !update {
		ret += fmt.Sprintf(`
  custom_tags = {
    "foo" = "bar"
  }
`)
	} else if withTags && update {
		ret += fmt.Sprintf(`
  custom_tags = {
    "foo" = "bar"
    "baz" = "bux"
  }
`)
	}
	return ret
}
