// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPolicy_importBasic(t *testing.T) {
	name := "test-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testResourcePolicy_initialConfig(name),
				Check:  testResourcePolicy_initialCheck(name),
			},
			{
				ResourceName:      "vault_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
