// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

var (
	messageBase64 = base64.StdEncoding.EncodeToString([]byte("Vault will be unavailable for maintenance on 2024-02-28 from 05:00Z to 07:00Z"))
)

func testConfigUICustomMessageConfig(isUpdate bool) string {
	if !isUpdate {
		return fmt.Sprintf(`
		resource "vault_config_ui_custom_message" "test" {
			title = "Maintenance Adviosry"
			message_base64 = "%s"
			start_time = "2024-02-01T00:00:00Z"						
		}`, messageBase64) // There's an intentional typo in the title
	} else {
		return fmt.Sprintf(`
		resource "vault_config_ui_custom_message" "test" {
			title = "Maintenance Advisory"
			message_base64 = "%s"
			start_time = "2024-02-01T00:00:00Z"
			end_time = "2024-02-27T23:59:59Z"
			type = "modal"
			authenticated = false
			link {
				title = "Learn more"
				href = "https://www.hashicorp.com"
			}
			options = {
				"background-color" = "red"
			}
		}`, messageBase64) // That intentional typo in the title is fixed here
	}
}

func TestAccConfigUICustomMessage(t *testing.T) {
	resourceName := "vault_config_ui_custom_message.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testConfigUICustomMessageConfig(false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldTitle, "Maintenance Adviosry"), // Checking that intentional typo
					resource.TestCheckResourceAttr(resourceName, consts.FieldMessageBase64, messageBase64),
					resource.TestCheckResourceAttr(resourceName, consts.FieldStartTime, "2024-02-01T00:00:00Z"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEndTime, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "banner"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuthenticated, "true"),
				),
			},
			{
				Config: testConfigUICustomMessageConfig(true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldTitle, "Maintenance Advisory"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMessageBase64, messageBase64),
					resource.TestCheckResourceAttr(resourceName, consts.FieldStartTime, "2024-02-01T00:00:00Z"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEndTime, "2024-02-27T23:59:59Z"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "modal"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuthenticated, "false"),
					resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("%s.0.title", consts.FieldLink), "Learn more"),
					resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("%s.0.href", consts.FieldLink), "https://www.hashicorp.com"),
					resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("%s.background-color", consts.FieldOptions), "red"),
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
