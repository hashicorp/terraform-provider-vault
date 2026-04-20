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

func TestAccSysConfigCORS(t *testing.T) {
	resourceName := "vault_sys_config_cors.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSysConfigCORSConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedOrigins+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrigins+".*", "http://www.example.com"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrigins+".*", "https://app.example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedHeaders+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedHeaders+".*", "X-Custom-Header-1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedHeaders+".*", "X-Custom-Header-2"),
				),
			},
			{
				Config: testAccSysConfigCORSConfig_updated(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedOrigins+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrigins+".*", "http://www.example.com"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrigins+".*", "https://app.example.com"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrigins+".*", "https://api.example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedHeaders+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedHeaders+".*", "X-Request-ID"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        "sys/config/cors",
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}

func TestAccSysConfigCORS_wildcard(t *testing.T) {
	resourceName := "vault_sys_config_cors.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSysConfigCORSConfig_wildcard(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedOrigins+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrigins+".*", "*"),
				),
			},
		},
	})
}

func TestAccSysConfigCORS_emptyHeaders(t *testing.T) {
	resourceName := "vault_sys_config_cors.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSysConfigCORSConfig_emptyHeaders(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedOrigins+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrigins+".*", "http://www.example.com"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedOrigins+".*", "https://app.example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedHeaders+".#", "0"),
				),
			},
		},
	})
}

func testAccSysConfigCORSConfig_basic() string {
	return `
resource "vault_sys_config_cors" "test" {
  allowed_origins = [
    "http://www.example.com",
    "https://app.example.com"
  ]
  
  allowed_headers = [
    "X-Custom-Header-1",
    "X-Custom-Header-2"
  ]
}
`
}

func testAccSysConfigCORSConfig_updated() string {
	return `
resource "vault_sys_config_cors" "test" {
  
  allowed_origins = [
    "http://www.example.com",
    "https://app.example.com",
    "https://api.example.com"
  ]
  
  allowed_headers = [
    "X-Request-ID"
  ]
}
`
}

func testAccSysConfigCORSConfig_wildcard() string {
	return `
resource "vault_sys_config_cors" "test" {
  allowed_origins = ["*"]
}
`
}

func testAccSysConfigCORSConfig_emptyHeaders() string {
	return `
resource "vault_sys_config_cors" "test" {
  allowed_origins = [
    "http://www.example.com",
    "https://app.example.com"
  ]
  
  allowed_headers = []
}
`
}
