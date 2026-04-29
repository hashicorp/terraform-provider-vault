// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccPolicyDataSource(t *testing.T) {
	name := acctest.RandomWithPrefix("test-policy")
	dataSourceName := "data.vault_policy.test"
	resourceName := "vault_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyDataSourceConfig(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, name),
					resource.TestCheckResourceAttrPair(dataSourceName, consts.FieldPolicy, resourceName, consts.FieldPolicy),
				),
			},
		},
	})
}

func TestAccPolicyDataSource_NS(t *testing.T) {
	name := acctest.RandomWithPrefix("test-policy")
	ns := acctest.RandomWithPrefix("ns")
	dataSourceName := "data.vault_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyDataSourceConfigNS(name, ns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldNamespace, ns),
				),
			},
		},
	})
}

func testAccPolicyDataSourceConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name   = %q
  policy = <<-EOT
    path "secret/*" {
      capabilities = ["read"]
    }
  EOT
}

data "vault_policy" "test" {
  name       = vault_policy.test.name
  depends_on = [vault_policy.test]
}
`, name)
}

func testAccPolicyDataSourceConfigNS(name, ns string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_policy" "test" {
  namespace = vault_namespace.test.path
  name      = %q
  policy    = <<-EOT
    path "secret/*" {
      capabilities = ["read"]
    }
  EOT
}

data "vault_policy" "test" {
  namespace  = vault_namespace.test.path
  name       = vault_policy.test.name
  depends_on = [vault_policy.test]
}
`, ns, name)
}
