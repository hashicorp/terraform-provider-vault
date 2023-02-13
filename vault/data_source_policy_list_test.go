// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourcePolicyList(t *testing.T) {
	datasourceName := "data.vault_policy_list.test"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourcePolicyListConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, "names.#", "2"),
					resource.TestCheckResourceAttr(datasourceName, "names.0", "one"),
					resource.TestCheckResourceAttr(datasourceName, "names.1", "two"),
				),
			},
		},
	})
}

func testDataSourcePolicyListConfig() string {
	config := `
	resource "vault_policy" "one" {
		name = "one"
	
		policy = <<EOT
	path "secret/my_app" {
	  capabilities = ["update"]
	}
	EOT
	}
	
	resource "vault_policy" "two" {
		name = "two"
	
		policy = <<EOT
	path "secret/my_app" {
	  capabilities = ["update"]
	}
	EOT
	}
	
	`

	return config
}
