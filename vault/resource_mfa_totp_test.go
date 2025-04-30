// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFATOTPBasic(t *testing.T) {
	var p *schema.Provider
	path := acctest.RandomWithPrefix("mfa-totp")
	resourceName := "vault_mfa_totp.test"

	var id string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		Steps: []resource.TestStep{
			{
				Config: testMFATOTPConfig(path, 20),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", path),
					resource.TestCheckResourceAttr(resourceName, "issuer", "hashicorp"),
					resource.TestCheckResourceAttr(resourceName, "period", "60"),
					resource.TestCheckResourceAttr(resourceName, "algorithm", "SHA256"),
					resource.TestCheckResourceAttr(resourceName, "digits", "8"),
					resource.TestCheckResourceAttr(resourceName, "key_size", "20"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					resp, err := client.Logical().Read(mfaTOTPPath(path))
					if err != nil {
						t.Fatal(err)
					}

					id = resp.Data["id"].(string)
					if id == "" {
						t.Fatal("expected ID to be set; got empty")
					}
				},
				Config: testMFATOTPConfig(path, 30),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					testCheckNotResourceAttr(resourceName, "id", id),
					resource.TestCheckResourceAttr(resourceName, "name", path),
					resource.TestCheckResourceAttr(resourceName, "issuer", "hashicorp"),
					resource.TestCheckResourceAttr(resourceName, "period", "60"),
					resource.TestCheckResourceAttr(resourceName, "algorithm", "SHA256"),
					resource.TestCheckResourceAttr(resourceName, "digits", "8"),
					resource.TestCheckResourceAttr(resourceName, "key_size", "30"),
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
