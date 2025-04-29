// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccMount_importBasic(t *testing.T) {
	var p *schema.Provider
	path := "test-" + acctest.RandString(10)
	cfg := testMountConfig{
		path:      path,
		mountType: "kv",
		version:   "1",
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
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
