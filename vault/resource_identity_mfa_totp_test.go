// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/mfa"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestIdentityMFATOTP(t *testing.T) {
	t.Parallel()

	resourceName := mfa.ResourceNameTOTP + ".test"

	checksCommon := []resource.TestCheckFunc{
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldUUID),
		resource.TestCheckResourceAttrSet(resourceName, consts.FieldMethodID),
		resource.TestCheckResourceAttr(resourceName, consts.FieldNamespaceID, "root"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldType, mfa.MethodTypeTOTP),
	}

	importTestStep := testutil.GetImportTestStep(resourceName, false, nil)
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  issuer  = "issuer1"
}
`, mfa.ResourceNameTOTP),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldIssuer, "issuer1"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldPeriod, "30"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldKeySize, "20"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldQRSize, "200"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "SHA256"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldDigits, "6"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldSkew, "1"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldMaxValidationAttempts, "5"),
					)...),
			},
			importTestStep,
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  issuer                  = "issuer2"
  period                  = 60
  key_size                = 30
  algorithm               = "SHA512"
  digits                  = 8
  skew                    = 0
  max_validation_attempts = 10
  qr_size                 = 300
}
`, mfa.ResourceNameTOTP),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldIssuer, "issuer2"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldPeriod, "60"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldKeySize, "30"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldQRSize, "300"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "SHA512"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldDigits, "8"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldSkew, "0"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldMaxValidationAttempts, "10"),
					)...),
			},
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  issuer                  = "issuer2"
  period                  = 60
  key_size                = 30
  algorithm               = "SHA512"
  digits                  = 8
  skew                    = 0
  max_validation_attempts = 10
  qr_size                 = 0
}
`, mfa.ResourceNameTOTP),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checksCommon,
						resource.TestCheckResourceAttr(resourceName, consts.FieldIssuer, "issuer2"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldPeriod, "60"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldKeySize, "30"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldQRSize, "0"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "SHA512"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldDigits, "8"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldSkew, "0"),
						resource.TestCheckResourceAttr(resourceName, consts.FieldMaxValidationAttempts, "10"),
					)...),
			},
			importTestStep,
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  issuer                  = "issuer2"
  algorithm               = "SHA5120"
}
`, mfa.ResourceNameTOTP),
				ExpectError: regexp.MustCompile(`Error running pre-apply refresh.*`),
			},
			{
				Config: fmt.Sprintf(`
resource "%s" "test" {
  issuer                  = "issuer2"
}
`, mfa.ResourceNameTOTP),
			},
		},
	})
}
