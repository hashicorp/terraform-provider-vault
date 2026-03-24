// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func TestAccConfigControlGroup(t *testing.T) {
	resourceName := "vault_config_control_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccConfigControlGroupCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigControlGroupConfig("24h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "86400"),
					testAccConfigControlGroupCheckExists(resourceName, "86400"),
				),
			},
			{
				Config: testAccConfigControlGroupConfig("48h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "172800"),
					testAccConfigControlGroupCheckExists(resourceName, "172800"),
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

func testAccConfigControlGroupCheckExists(resourceName, expectedMaxTTL string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state: %s", resourceName)
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		resp, err := client.Logical().Read(controlGroupPath)
		if err != nil {
			return fmt.Errorf("error reading control group config: %w", err)
		}
		if resp == nil {
			return fmt.Errorf("control group config does not exist")
		}

		actualMaxTTL, ok := resp.Data[consts.FieldMaxTTL]
		if !ok {
			return fmt.Errorf("control group config missing %q", consts.FieldMaxTTL)
		}

		if fmt.Sprintf("%v", actualMaxTTL) != expectedMaxTTL {
			return fmt.Errorf("unexpected control group %s: got %v, want %s", consts.FieldMaxTTL, actualMaxTTL, expectedMaxTTL)
		}

		return nil
	}
}

func testAccConfigControlGroupCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_config_control_group" {
			continue
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		resp, err := client.Logical().Read(controlGroupPath)
		if err != nil {
			return fmt.Errorf("error reading control group config during destroy check: %w", err)
		}
		if resp == nil {
			continue
		}

		value, ok := resp.Data[consts.FieldMaxTTL]
		if !ok {
			continue
		}

		actual := fmt.Sprintf("%v", value)
		if actual == "" || actual == "0" || actual == "0s" {
			continue
		}

		return fmt.Errorf("control group config still exists with %s=%s", consts.FieldMaxTTL, actual)
	}

	return nil
}
