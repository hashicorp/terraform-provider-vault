// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccMount_importBasic(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg := testMountConfig{
		path:      path,
		mountType: "kv",
		version:   "1",
	}
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_initialConfig(cfg),
				Check:  testResourceMount_initialCheck(cfg),
			},
			{
				ResourceName:      "vault_mount.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
