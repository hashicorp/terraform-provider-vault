// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func TestMFATOTPBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("mfa-totp")
	resourceName := "vault_mfa_totp.test"

	var id string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testMFATOTPConfig(path, 20),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuer, "hashicorp"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPeriod, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "SHA256"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDigits, "8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeySize, "20"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxValidationAttempts, "5"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
				),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					resp, err := client.Logical().Read(mfaTOTPPath(path))
					if err != nil {
						t.Fatal(err)
					}

					id = resp.Data[consts.FieldID].(string)
					if id == "" {
						t.Fatal("expected ID to be set; got empty")
					}
				},
				Config: testMFATOTPConfigUpdate(path, 30, 10),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
					testCheckNotResourceAttr(resourceName, consts.FieldID, id),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuer, "hashicorp"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPeriod, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithm, "SHA256"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDigits, "8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeySize, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxValidationAttempts, "10"),
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

func TestMFATOTPNegativeScenarios(t *testing.T) {
	resourceName := "vault_mfa_totp.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      testMFATOTPConfigUpdate(acctest.RandomWithPrefix("mfa-totp-negative"), 20, -1),
				ExpectError: regexp.MustCompile("max_validation_attempts must be greater than zero"),
			},
			{
				Config: testMFATOTPConfigUpdate(acctest.RandomWithPrefix("mfa-totp-zero"), 20, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxValidationAttempts, "5"),
				),
			},
		},
	})
}

func testCheckNotResourceAttr(name, key, value string) resource.TestCheckFunc {
	return func(state *terraform.State) error {
		if err := resource.TestCheckResourceAttr(name, key, value); err == nil {
			return fmt.Errorf("expected value %s to change for key %s.%s", value, name, key)
		}

		return nil
	}
}

func testMFATOTPConfig(path string, keySize int) string {
	return fmt.Sprintf(`
resource "vault_mfa_totp" "test" {
  name      = "%s"
  issuer    = "hashicorp"
  period    = 60
  algorithm = "SHA256"
  digits    = 8
  key_size  = %d
}
`, path, keySize)
}

func testMFATOTPConfigUpdate(path string, keySize int, maxValidationAttempts int) string {
	return fmt.Sprintf(`
resource "vault_mfa_totp" "test" {
  name                    = "%s"
  issuer                  = "hashicorp"
  period                  = 60
  algorithm               = "SHA256"
  digits                  = 8
  key_size                = %d
  max_validation_attempts = %d
}
`, path, keySize, maxValidationAttempts)
}
