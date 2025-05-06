// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
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
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceAuthBackendsBasic,
				// The token auth method is built-in and automatically enabled
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(ds, consts.FieldPaths+".#", "1"),
					resource.TestCheckResourceAttr(ds, consts.FieldPaths+".0", "token"),
					resource.TestCheckResourceAttr(ds, consts.FieldAccessors+".#", "1"),
				),
			},
			{
				Config: testDataSourceAuthBackendsBasic_config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(ds, consts.FieldPaths+".#", "3"),
					resource.TestCheckResourceAttr(ds, consts.FieldAccessors+".#", "3"),
					resource.TestCheckResourceAttr(ds, consts.FieldType, ""),
					// Using sorted outputs for testing consistency; API returns unsorted
					resource.TestCheckOutput(consts.FieldPath+"0", "approle"),
					resource.TestCheckOutput(consts.FieldPath+"1", "token"),
					resource.TestCheckOutput(consts.FieldPath+"2", "userpass"),
				),
			},
			{
				Config: testDataSourceAuthBackends_config([]string{userpassPath, approlePath}, "userpass"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(ds, consts.FieldPaths+".#", "1"),
					resource.TestCheckResourceAttr(ds, consts.FieldPaths+".0", userpassPath),
					resource.TestCheckResourceAttr(ds, consts.FieldAccessors+".#", "1"),
					resource.TestCheckResourceAttr(ds, consts.FieldType, "userpass"),
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
output "path0" {
	value = sort(data.vault_auth_backends.test.paths).0
}
output "path1" {
	value = sort(data.vault_auth_backends.test.paths).1
}
output "path2" {
	value = sort(data.vault_auth_backends.test.paths).2
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
