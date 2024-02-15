// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAuditRequestHeader(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	newName := acctest.RandomWithPrefix("tf-test-new")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAuditRequestHeaderCheckDestroy(name, newName),
		Steps: []resource.TestStep{
			{
				Config: testAuditRequestHeader_Config(name, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_audit_request_header.header", "name", name),
					resource.TestCheckResourceAttr("vault_audit_request_header.header", "hmac", "false"),
				),
			},
			{
				Config: testAuditRequestHeader_Config(name, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_audit_request_header.header", "name", name),
					resource.TestCheckResourceAttr("vault_audit_request_header.header", "hmac", "true"),
				),
			},
			{
				Config: testAuditRequestHeader_Config(newName, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_audit_request_header.header", "name", newName),
					resource.TestCheckResourceAttr("vault_audit_request_header.header", "hmac", "true"),
				),
			},
		},
	})
}

func testAuditRequestHeaderCheckDestroy(names ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

		for _, name := range names {
			resp, err := client.Logical().Read(auditRequestHeaderPath(name))
			if err != nil {
				// This endpoint returns a 400 if the header does not exist, rather than
				// a 404/empty response.
				if apiErr, ok := err.(*api.ResponseError); !ok ||
					apiErr.StatusCode != 400 || len(apiErr.Errors) != 1 ||
					apiErr.Errors[0] != "Could not find header in config" {

					return err
				}
			}

			if resp != nil {
				return fmt.Errorf("Resource Audit Request Header %s still exists", name)
			}
		}

		return nil
	}
}

func testAuditRequestHeader_Config(name string, hmac bool) string {
	return fmt.Sprintf(`
resource "vault_audit_request_header" "header" {
  name = "%s"
  hmac = %v
}
`, name, hmac)
}
