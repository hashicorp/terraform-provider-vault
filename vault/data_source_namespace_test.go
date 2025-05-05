// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceNamespace(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	resourceName := "data.vault_namespace"
	path := acctest.RandomWithPrefix("tf-ns")
	pathChild := acctest.RandomWithPrefix("tf-child")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testNamespaceDestroy(path),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNamespaceConfig_nested(path, pathChild),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName+".parent", consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName+".parent", consts.FieldPathFQ, path),
					resource.TestCheckResourceAttrSet(resourceName+".parent", consts.FieldNamespaceID),

					resource.TestCheckResourceAttr(resourceName+".child", consts.FieldPath, pathChild),
					resource.TestCheckResourceAttr(resourceName+".child", consts.FieldPathFQ, fmt.Sprintf("%s/%s", path, pathChild)),
					resource.TestCheckResourceAttrSet(resourceName+".child", consts.FieldNamespaceID),
				),
			},
		},
	})

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testNamespaceDestroy(path),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNamespaceConfig_customMetadata(path),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName+".test", consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName+".test", consts.FieldCustomMetadata+".%", "2"),
					resource.TestCheckResourceAttr(resourceName+".test", consts.FieldCustomMetadata+".foo", "abc"),
					resource.TestCheckResourceAttr(resourceName+".test", consts.FieldCustomMetadata+".zip", "zap"),
				),
			},
		},
	})

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testNamespaceDestroy(path),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNamespaceConfig_current(path),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName+".current", consts.FieldPath, ""),
					resource.TestCheckResourceAttr(resourceName+".current", consts.FieldPathFQ, ""),

					resource.TestCheckResourceAttr(resourceName+".test", consts.FieldPath, ""),
					resource.TestCheckResourceAttr(resourceName+".test", consts.FieldPathFQ, path),
				),
			},
		},
	})
}

func testAccDataSourceNamespaceConfig_nested(parentPath string, childPath string) string {
	config := fmt.Sprintf(`
resource "vault_namespace" "parent" {
  path = %q
}

resource "vault_namespace" "child" {
  namespace = vault_namespace.parent.path
  path      = %q
}

data "vault_namespace" "parent" {
  path = vault_namespace.parent.path
}

data "vault_namespace" "child" {
  namespace = vault_namespace.child.namespace
  path      = vault_namespace.child.path
}
	`, parentPath, childPath)

	return config
}

func testAccDataSourceNamespaceConfig_customMetadata(path string) string {
	config := fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
  custom_metadata = {
    foo = "abc"
    zip = "zap"
  }
}

data "vault_namespace" "test" {
  path = vault_namespace.test.path
}
	`, path)

	return config
}

func testAccDataSourceNamespaceConfig_current(path string) string {
	config := fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

data "vault_namespace" "current" {}

data "vault_namespace" "test" {
  namespace = vault_namespace.test.path
}
	`, path)

	return config
}
