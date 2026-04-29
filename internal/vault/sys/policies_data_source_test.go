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

func TestAccPoliciesDataSource(t *testing.T) {
	prefix := acctest.RandomWithPrefix("test-policies")
	nameA := prefix + "-alpha"
	nameB := prefix + "-bravo"
	dataSourceAll := "data.vault_policies.all"
	dataSourceFiltered := "data.vault_policies.filtered"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPoliciesDataSourceConfig(nameA, nameB, prefix),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckTypeSetElemAttr(dataSourceAll, consts.FieldPolicies+".*", nameA),
					resource.TestCheckTypeSetElemAttr(dataSourceAll, consts.FieldPolicies+".*", nameB),
					resource.TestCheckResourceAttr(dataSourceFiltered, consts.FieldPolicies+".#", "1"),
					resource.TestCheckTypeSetElemAttr(dataSourceFiltered, consts.FieldPolicies+".*", nameA),
				),
			},
		},
	})
}

func TestAccPoliciesDataSource_NS(t *testing.T) {
	prefix := acctest.RandomWithPrefix("test-policies")
	nameA := prefix + "-alpha"
	nameB := prefix + "-bravo"
	ns := acctest.RandomWithPrefix("ns")
	dataSourceAll := "data.vault_policies.all"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPoliciesDataSourceConfigNS(nameA, nameB, ns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceAll, consts.FieldNamespace, ns),
					resource.TestCheckTypeSetElemAttr(dataSourceAll, consts.FieldPolicies+".*", nameA),
					resource.TestCheckTypeSetElemAttr(dataSourceAll, consts.FieldPolicies+".*", nameB),
				),
			},
		},
	})
}

func testAccPoliciesDataSourceConfig(nameA, nameB, prefix string) string {
	return fmt.Sprintf(`
resource "vault_policy" "alpha" {
  name   = %q
  policy = <<-EOT
    path "secret/*" {
      capabilities = ["read"]
    }
  EOT
}

resource "vault_policy" "bravo" {
  name   = %q
  policy = <<-EOT
    path "secret/*" {
      capabilities = ["read"]
    }
  EOT
}

data "vault_policies" "all" {
  depends_on = [vault_policy.alpha, vault_policy.bravo]
}

data "vault_policies" "filtered" {
  name_filter = "%s-alpha$"
  depends_on  = [vault_policy.alpha, vault_policy.bravo]
}
`, nameA, nameB, prefix)
}

func testAccPoliciesDataSourceConfigNS(nameA, nameB, ns string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_policy" "alpha" {
  namespace = vault_namespace.test.path
  name      = %q
  policy    = <<-EOT
    path "secret/*" {
      capabilities = ["read"]
    }
  EOT
}

resource "vault_policy" "bravo" {
  namespace = vault_namespace.test.path
  name      = %q
  policy    = <<-EOT
    path "secret/*" {
      capabilities = ["read"]
    }
  EOT
}

data "vault_policies" "all" {
  namespace  = vault_namespace.test.path
  depends_on = [vault_policy.alpha, vault_policy.bravo]
}
`, ns, nameA, nameB)
}
