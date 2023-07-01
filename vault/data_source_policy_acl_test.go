// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourcePolicyRead(t *testing.T) {
	datasourceName := "data.vault_policy_acl.test"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourcePolicyReadConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, "names.0", "one"),
					resource.TestCheckResourceAttr(datasourceName, "names.1", "two"),
				),
			},
		},
	})
}

func testDataSourcePolicyReadConfig() string {
	config := `
	resource "vault_policy" "one" {
		name = "one"
	
		policy = <<EOT
	path "secret/my_app" {
	  capabilities = ["update"]
	}
	EOT
	}

	data "vault_policy" "two" {
		policy_name = "one"
	}
	
	`

	return config
}
