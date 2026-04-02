// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccDataSourceSysConfigCORS(t *testing.T) {
	dataSourceName := "data.vault_sys_config_cors.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceSysConfigCORSConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldAllowedOrigins+".#", "2"),
					resource.TestCheckTypeSetElemAttr(dataSourceName, consts.FieldAllowedOrigins+".*", "http://www.example.com"),
					resource.TestCheckTypeSetElemAttr(dataSourceName, consts.FieldAllowedOrigins+".*", "https://app.example.com"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldAllowedHeaders+".#", "2"),
					resource.TestCheckTypeSetElemAttr(dataSourceName, consts.FieldAllowedHeaders+".*", "X-Custom-Header"),
					resource.TestCheckTypeSetElemAttr(dataSourceName, consts.FieldAllowedHeaders+".*", "X-Application-ID"),
				),
			},
		},
	})
}

func TestAccDataSourceSysConfigCORS_wildcard(t *testing.T) {
	dataSourceName := "data.vault_sys_config_cors.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceSysConfigCORSConfig_wildcard(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldAllowedOrigins+".#", "1"),
					resource.TestCheckTypeSetElemAttr(dataSourceName, consts.FieldAllowedOrigins+".*", "*"),
				),
			},
		},
	})
}

func TestAccDataSourceSysConfigCORS_notConfigured(t *testing.T) {
	dataSourceName := "data.vault_sys_config_cors.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceSysConfigCORSConfig_notConfigured(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldEnabled, "false"),
					resource.TestCheckNoResourceAttr(dataSourceName, consts.FieldAllowedOrigins+".#"),
					resource.TestCheckNoResourceAttr(dataSourceName, consts.FieldAllowedHeaders+".#"),
				),
			},
		},
	})
}

func testAccDataSourceSysConfigCORSConfig_basic() string {
	return `
resource "vault_sys_config_cors" "test" {
  allowed_origins = [
    "http://www.example.com",
    "https://app.example.com"
  ]
  
  allowed_headers = [
    "X-Custom-Header",
    "X-Application-ID"
  ]
}

data "vault_sys_config_cors" "test" {
  depends_on = [vault_sys_config_cors.test]
}
`
}

func testAccDataSourceSysConfigCORSConfig_wildcard() string {
	return `
resource "vault_sys_config_cors" "test" {
  allowed_origins = ["*"]
}

data "vault_sys_config_cors" "test" {
  depends_on = [vault_sys_config_cors.test]
}
`
}

func testAccDataSourceSysConfigCORSConfig_notConfigured() string {
	return `
# Read CORS configuration when it's not configured (disabled state)
# This tests the scenario where no vault_sys_config_cors resource exists
data "vault_sys_config_cors" "test" {}
`
}
