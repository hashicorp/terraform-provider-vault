// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

var config = `
resource "vault_mount" "test" {
  path        = "transit"
  type        = "transit"
  description = "This is an example mount"
}

resource "vault_transit_secret_backend_key" "test" {
  name  		   = "test"
  backend 		   = vault_mount.test.path
  deletion_allowed = true
  type             = "ecdsa-p256"
}

data "vault_transit_sign" "test" {
    path        = vault_mount.test.path
    name        = vault_transit_secret_backend_key.test.name
#	input = "aGVsbG8gd29ybGQuCg=="
batch_input = [{
      input = "adba32=="
      context = "abcd"
    },
    {
      input = "aGVsbG8gd29ybGQuCg=="
      context = "efgh"
	}
    ]
}
`

var batchConfig = `    {
      input = "adba32=="
      context = "abcd"
    },
    {
      input = "aGVsbG8gd29ybGQuCg=="
      context = "efgh"
    }`

func TestDataSourceTransitSign(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  testDataSourceTransitSign_check,
			},
		},
	})
}

func testDataSourceTransitSign_check(s *terraform.State) error {
	return nil
}
