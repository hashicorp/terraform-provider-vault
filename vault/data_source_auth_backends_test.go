// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceAuthBackends(t *testing.T) {
	userpassPath := acctest.RandomWithPrefix("foo")
	approlePath := acctest.RandomWithPrefix("foo")
	ds := "data.vault_auth_backends.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceAuthBackendsBasic,
				// The token auth method is built-in and automatically enabled
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckTypeSetElemAttr(ds, consts.FieldPaths+".*", "token"),
				),
			},
			{
				Config: testDataSourceAuthBackendsBasic_config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckTypeSetElemAttr(ds, consts.FieldPaths+".*", "userpass"),
					resource.TestCheckTypeSetElemAttr(ds, consts.FieldPaths+".*", "approle"),
					resource.TestCheckTypeSetElemAttr(ds, consts.FieldPaths+".*", "token"),
				),
			},
			{
				Config: testDataSourceAuthBackends_config([]string{userpassPath, approlePath}, "userpass"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(ds, consts.FieldType, "userpass"),
					resource.TestCheckTypeSetElemAttr(ds, consts.FieldPaths+".*", userpassPath),
					resource.TestCheckResourceAttrSet(ds, consts.FieldPaths+".#"),
					resource.TestCheckResourceAttrSet(ds, consts.FieldAccessors+".#"),
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
