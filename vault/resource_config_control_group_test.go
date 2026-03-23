// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestAccConfigControlGroupBasic(t *testing.T) {
	resourceName := "vault_config_control_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testAccConfigControlGroupConfig("24h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "86400"),
				),
			},
			{
				Config: testAccConfigControlGroupConfig("48h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "172800"),
				),
			},
		},
	})
}

func TestAccConfigControlGroupImport(t *testing.T) {
	resourceName := "vault_config_control_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testAccConfigControlGroupConfig("24h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "86400"),
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

func testAccConfigControlGroupConfig(maxTTL string) string {
	return fmt.Sprintf(`
resource "vault_config_control_group" "test" {
  max_ttl = "%s"
}
`, maxTTL)
}
