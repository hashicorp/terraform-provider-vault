// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceNamespaces(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	ns := acctest.RandomWithPrefix("tf-ns")
	resourceName := "data.vault_namespaces"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNamespacesConfig(ns, 3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName+".test", consts.FieldPaths+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test", consts.FieldPaths+".*", "test-0"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test", consts.FieldPaths+".*", "test-1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test", consts.FieldPaths+".*", "test-2"),

					resource.TestCheckResourceAttr(resourceName+".nested", consts.FieldPaths+".#", "0"),
				),
			},
		},
	})
}

func testAccDataSourceNamespacesConfig(ns string, count int) string {
	config := fmt.Sprintf(`
resource "vault_namespace" "parent" {
  path = %q
}

resource "vault_namespace" "test" {
  count     = %d
  namespace = vault_namespace.parent.path
  path      = "test-${count.index}"
}

resource "vault_namespace" "nested" {
  namespace = vault_namespace.test[0].path_fq
  path      = "nested"
}

data "vault_namespaces" "test" {
	namespace  = vault_namespace.parent.path
	depends_on = [vault_namespace.test]
}

data "vault_namespaces" "nested" {
	namespace  = vault_namespace.nested.path_fq
}
	`, ns, count)

	return config
}
