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
					resource.TestCheckResourceAttr(resourceName+".test_root", "recursive", "false"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_root", consts.FieldPaths+".*", ns),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_root", consts.FieldPathsFQ+".*", ns),

					resource.TestCheckResourceAttr(resourceName+".test_level0", "recursive", "false"),
					resource.TestCheckResourceAttr(resourceName+".test_level0", consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName+".test_level0", consts.FieldPaths+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0", consts.FieldPaths+".*", "level1-ns-0"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0", consts.FieldPaths+".*", "level1-ns-1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0", consts.FieldPaths+".*", "level1-ns-2"),
					resource.TestCheckResourceAttr(resourceName+".test_level0", consts.FieldPathsFQ+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0", consts.FieldPathsFQ+".*", ns+"/level1-ns-0"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0", consts.FieldPathsFQ+".*", ns+"/level1-ns-1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0", consts.FieldPathsFQ+".*", ns+"/level1-ns-2"),

					resource.TestCheckResourceAttr(resourceName+".test_level1", "recursive", "false"),
					resource.TestCheckResourceAttr(resourceName+".test_level1", consts.FieldNamespace, ns+"/level1-ns-0"),
					resource.TestCheckResourceAttr(resourceName+".test_level1", consts.FieldPaths+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level1", consts.FieldPaths+".*", "level2-ns-0"),
					resource.TestCheckResourceAttr(resourceName+".test_level1", consts.FieldPathsFQ+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level1", consts.FieldPathsFQ+".*", ns+"/level1-ns-0/level2-ns-0"),

					resource.TestCheckResourceAttr(resourceName+".test_level2", "recursive", "false"),
					resource.TestCheckResourceAttr(resourceName+".test_level2", consts.FieldNamespace, ns+"/level1-ns-0/level2-ns-0"),
					resource.TestCheckResourceAttr(resourceName+".test_level2", consts.FieldPaths+".#", "0"),
					resource.TestCheckResourceAttr(resourceName+".test_level2", consts.FieldPathsFQ+".#", "0"),

					resource.TestCheckResourceAttr(resourceName+".test_root_recursive", "recursive", "true"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_root_recursive", consts.FieldPaths+".*", ns+"/level1-ns-0/level2-ns-0"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_root_recursive", consts.FieldPathsFQ+".*", ns+"/level1-ns-0/level2-ns-0"),

					resource.TestCheckResourceAttr(resourceName+".test_level0_recursive", "recursive", "true"),
					resource.TestCheckResourceAttr(resourceName+".test_level0_recursive", consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName+".test_level0_recursive", consts.FieldPaths+".#", "4"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0_recursive", consts.FieldPaths+".*", "level1-ns-0"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0_recursive", consts.FieldPaths+".*", "level1-ns-0/level2-ns-0"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0_recursive", consts.FieldPaths+".*", "level1-ns-1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0_recursive", consts.FieldPaths+".*", "level1-ns-2"),
					resource.TestCheckResourceAttr(resourceName+".test_level0_recursive", consts.FieldPathsFQ+".#", "4"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0_recursive", consts.FieldPathsFQ+".*", ns+"/level1-ns-0"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0_recursive", consts.FieldPathsFQ+".*", ns+"/level1-ns-0/level2-ns-0"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0_recursive", consts.FieldPathsFQ+".*", ns+"/level1-ns-1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level0_recursive", consts.FieldPathsFQ+".*", ns+"/level1-ns-2"),

					resource.TestCheckResourceAttr(resourceName+".test_level1_recursive", "recursive", "true"),
					resource.TestCheckResourceAttr(resourceName+".test_level1_recursive", consts.FieldNamespace, ns+"/level1-ns-0"),
					resource.TestCheckResourceAttr(resourceName+".test_level1_recursive", consts.FieldPaths+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level1_recursive", consts.FieldPaths+".*", "level2-ns-0"),
					resource.TestCheckResourceAttr(resourceName+".test_level1_recursive", consts.FieldPathsFQ+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName+".test_level1_recursive", consts.FieldPathsFQ+".*", ns+"/level1-ns-0/level2-ns-0"),

					resource.TestCheckResourceAttr(resourceName+".test_level2_recursive", "recursive", "true"),
					resource.TestCheckResourceAttr(resourceName+".test_level2_recursive", consts.FieldNamespace, ns+"/level1-ns-0/level2-ns-0"),
					resource.TestCheckResourceAttr(resourceName+".test_level2_recursive", consts.FieldPaths+".#", "0"),
					resource.TestCheckResourceAttr(resourceName+".test_level2_recursive", consts.FieldPathsFQ+".#", "0"),
				),
			},
		},
	})
}

func testAccDataSourceNamespacesConfig(ns string, count int) string {
	config := fmt.Sprintf(`
resource "vault_namespace" "level0" {
  path = %q
}

resource "vault_namespace" "level1" {
  count     = %d
  namespace = vault_namespace.level0.path_fq
  path      = "level1-ns-${count.index}"
}

# this will create a namespace with the path "level0-ns/level1-ns-0/level2-ns-0"
resource "vault_namespace" "level2" {
  namespace = vault_namespace.level1[0].path_fq
  path      = "level2-ns-0"
}

data "vault_namespaces" "test_root" {
  depends_on = [vault_namespace.level0, vault_namespace.level1, vault_namespace.level2]
}

data "vault_namespaces" "test_level0" {
  namespace  = vault_namespace.level0.path_fq
  depends_on = [vault_namespace.level1, vault_namespace.level2]
}

data "vault_namespaces" "test_level1" {
  namespace  = vault_namespace.level1[0].path_fq
  depends_on = [vault_namespace.level1, vault_namespace.level2]
}

data "vault_namespaces" "test_level2" {
  namespace  = vault_namespace.level2.path_fq
  depends_on = [vault_namespace.level1, vault_namespace.level2]
}

data "vault_namespaces" "test_root_recursive" {
  recursive  = true
  depends_on = [vault_namespace.level0, vault_namespace.level1, vault_namespace.level2]
}

data "vault_namespaces" "test_level0_recursive" {
  namespace  = vault_namespace.level0.path_fq
  recursive  = true
  depends_on = [vault_namespace.level1, vault_namespace.level2]
}

data "vault_namespaces" "test_level1_recursive" {
  namespace  = vault_namespace.level1[0].path_fq
  recursive  = true
  depends_on = [vault_namespace.level1, vault_namespace.level2]
}

data "vault_namespaces" "test_level2_recursive" {
  namespace  = vault_namespace.level2.path_fq
  recursive  = true
  depends_on = [vault_namespace.level1, vault_namespace.level2]
}
	`, ns, count)

	return config
}
