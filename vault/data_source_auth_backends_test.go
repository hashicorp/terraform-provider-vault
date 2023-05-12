// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceAuthBackends(t *testing.T) {
	userpassPath := acctest.RandomWithPrefix("foo")
	approlePath := acctest.RandomWithPrefix("foo")
	ds := "data.vault_auth_backends.test"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceAuthBackendsBasic,
				// The token auth method is built-in and automatically enabled
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(ds, "paths.#", "1"),
					resource.TestCheckResourceAttr(ds, "paths.0", "token"),
					resource.TestCheckResourceAttr(ds, "accessors.#", "1"),
				),
			},
			{
				Config: testDataSourceAuthBackendsBasic_config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(ds, "paths.#", "3"),
					resource.TestCheckResourceAttr(ds, "paths.0", "approle"),
					resource.TestCheckResourceAttr(ds, "paths.1", "token"),
					resource.TestCheckResourceAttr(ds, "paths.2", "userpass"),
					resource.TestCheckResourceAttr(ds, "accessors.#", "3"),
					resource.TestCheckResourceAttr(ds, "type", ""),
				),
			},
			{
				Config: testDataSourceAuthBackends_config([]string{userpassPath, approlePath}, "userpass"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(ds, "paths.#", "1"),
					resource.TestCheckResourceAttr(ds, "paths.0", userpassPath),
					resource.TestCheckResourceAttr(ds, "accessors.#", "1"),
					resource.TestCheckResourceAttr(ds, "type", "userpass"),
				),
			},
		},
	})
}

var testDataSourceAuthBackendsBasic = `
data "vault_auth_backends" "test" {}
`

var testDataSourceAuthBackendsBasic_config = `
resource "vault_auth_backend" "userpass" {
	type = "userpass"
}
resource "vault_auth_backend" "approle" {
	type = "approle"
}
data "vault_auth_backends" "test" {
	depends_on = [
		vault_auth_backend.userpass,
		vault_auth_backend.approle,
	]
}
`

func testDataSourceAuthBackends_config(path []string, typ string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test-foo" {
	path = "%s"
	type = "userpass"
}
resource "vault_auth_backend" "test-bar" {
	path = "%s"
	type = "approle"
}
data "vault_auth_backends" "test" {
	depends_on = [
		vault_auth_backend.test-foo,
		vault_auth_backend.test-bar,
	]
	type = "%s"
}
`, path[0], path[1], typ)
}
