// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func TestAccDataSourceNamespace(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-ns")
	pathChild := acctest.RandomWithPrefix("tf-child")

	client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
	providerNS := mountutil.TrimSlashes(client.Namespace())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testNamespaceDestroy(path),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNamespaceConfig_nested(path, pathChild),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_namespace.parent", consts.FieldPath, path),
					resource.TestCheckResourceAttr("data.vault_namespace.parent", consts.FieldPathFQ, path),
					resource.TestCheckResourceAttr("data.vault_namespace.parent", consts.FieldID, fmt.Sprintf("%s/%s/", providerNS, path)),
					resource.TestCheckResourceAttrSet("data.vault_namespace.parent", consts.FieldNamespaceID),

					resource.TestCheckResourceAttr("data.vault_namespace.child", consts.FieldPath, pathChild),
					resource.TestCheckResourceAttr("data.vault_namespace.child", consts.FieldPathFQ, fmt.Sprintf("%s/%s", path, pathChild)),
					resource.TestCheckResourceAttr("data.vault_namespace.child", consts.FieldID, fmt.Sprintf("%s/%s/%s/", providerNS, path, pathChild)),
					resource.TestCheckResourceAttrSet("data.vault_namespace.child", consts.FieldNamespaceID),
				),
			},
		},
	})

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testNamespaceDestroy(path),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNamespaceConfig_customMetadata(path),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_namespace.test", consts.FieldPath, path),
					resource.TestCheckResourceAttr("data.vault_namespace.test", consts.FieldCustomMetadata+".%", "2"),
					resource.TestCheckResourceAttr("data.vault_namespace.test", consts.FieldCustomMetadata+".foo", "abc"),
					resource.TestCheckResourceAttr("data.vault_namespace.test", consts.FieldCustomMetadata+".zip", "zap"),
				),
			},
		},
	})

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testNamespaceDestroy(pathChild),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNamespaceConfig_current(pathChild),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_namespace.current", consts.FieldPath, ""),
					resource.TestCheckResourceAttr("data.vault_namespace.current", consts.FieldPathFQ, ""),
					resource.TestCheckResourceAttr("data.vault_namespace.current", consts.FieldID, fmt.Sprintf("%s/", providerNS)),

					resource.TestCheckResourceAttr("data.vault_namespace.child", consts.FieldPath, ""),
					resource.TestCheckResourceAttr("data.vault_namespace.child", consts.FieldPathFQ, pathChild),
					resource.TestCheckResourceAttr("data.vault_namespace.child", consts.FieldID, fmt.Sprintf("%s/%s/", providerNS, pathChild)),
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

func testAccDataSourceNamespaceConfig_current(childPath string) string {
	config := fmt.Sprintf(`
resource "vault_namespace" "child" {
  path = %q
}

data "vault_namespace" "current" {}

data "vault_namespace" "child" {
  namespace = vault_namespace.child.path
}
	`, childPath)

	return config
}
