// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccNamespace(t *testing.T) {
	namespacePath := acctest.RandomWithPrefix("parent-ns")
	resourceNameParent := "vault_namespace.parent"
	resourceNameChild := "vault_namespace.child"

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceNameParent, consts.FieldPath, namespacePath),
	}
	getNestedChecks := func(count int) []resource.TestCheckFunc {
		var checks []resource.TestCheckFunc
		for i := 0; i < count; i++ {
			rsc := fmt.Sprintf("%s.%d", resourceNameChild, i)
			checks = append(checks,
				resource.TestCheckResourceAttr(
					rsc, consts.FieldPath,
					fmt.Sprintf("child_%d", i)),
			)
			checks = append(checks,
				resource.TestCheckResourceAttr(
					rsc, consts.FieldPathFQ,
					fmt.Sprintf("%s/child_%d", namespacePath, i)),
			)
		}
		return checks
	}

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testNamespaceDestroy(namespacePath),
		Steps: []resource.TestStep{
			{
				Config: testNestedNamespaces(namespacePath, 3),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checks, getNestedChecks(3)...)...,
				),
			},
			{
				Config:  testNestedNamespaces(namespacePath+"/", 3),
				Destroy: false,
				ExpectError: regexp.MustCompile(
					fmt.Sprintf(`value "%s/" for "path" contains leading/trailing "%s"`,
						namespacePath, consts.PathDelim)),
			},
			{
				Config:  testNestedNamespaces("/"+namespacePath, 3),
				Destroy: false,
				ExpectError: regexp.MustCompile(
					fmt.Sprintf(`value "/%s" for "path" contains leading/trailing "%s"`,
						namespacePath, consts.PathDelim)),
			},
			{
				Config:  testNestedNamespaces("/"+namespacePath+"/", 3),
				Destroy: false,
				ExpectError: regexp.MustCompile(
					fmt.Sprintf(`value "/%s/" for "path" contains leading/trailing "%s"`,
						namespacePath, consts.PathDelim)),
			},
			{
				Config: testNestedNamespaces(namespacePath, 2),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checks, getNestedChecks(2)...)...,
				),
			},
			{
				Config: testNestedNamespaces(namespacePath, 0),
				Check: resource.ComposeAggregateTestCheckFunc(
					append(checks, getNestedChecks(0)...)...,
				),
			},
			{
				Config: testNestedNamespaces(namespacePath+"-foo", 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameParent, consts.FieldPath, namespacePath+"-foo"),
					testNamespaceDestroy(namespacePath)),
			},
			{
				SkipFunc: func() (bool, error) {
					return !testProvider.Meta().(*provider.ProviderMeta).IsAPISupported(provider.VaultVersion112), nil
				},
				Config: testNamespaceCustomMetadata(namespacePath + "-cm"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameParent, consts.FieldPath, namespacePath+"-cm"),
					resource.TestCheckResourceAttr(resourceNameParent, "custom_metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceNameParent, "custom_metadata.foo", "abc"),
					resource.TestCheckResourceAttr(resourceNameParent, "custom_metadata.bar", "123"),
					testNamespaceDestroy(namespacePath)),
			},
		},
	})
}

func TestAccNamespace_customDiff(t *testing.T) {
	namespacePath := acctest.RandomWithPrefix("tf-ns")
	parentNSPath := acctest.RandomWithPrefix("parent-ns")
	resourceName := "vault_namespace.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testNamespaceDestroy(namespacePath),
		Steps: []resource.TestStep{
			{
				Config: testNamespaceCustomDiffConfig_basic(namespacePath, parentNSPath, "admin"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, namespacePath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, "admin/"+parentNSPath),
				),
			},
			{
				Config: testNamespaceCustomDiffConfig_updated(namespacePath, parentNSPath, "admin"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, namespacePath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, "parent"),
				),
			},
		},
	})
}

func testNamespaceCustomDiffConfig_basic(path, parentPath, providerNS string) string {
	ret := fmt.Sprintf(`
provider "vault" {
	auth_login {
    path = "auth/userpass/login/${var.username}"
    parameters = {
      password = "secret"
    }
  }
}

resource "vault_namespace" "parent" {
  path                   = "%s"
  namespace              = "%s"
}

resource "vault_namespace" "test" {
  path                   = "%s"
  namespace              = "%s/${vault_namespace.parent.path}"
}
`, parentPath, providerNS, path, providerNS)

	return ret
}

func testNamespaceCustomDiffConfig_updated(path, parentNSPath, providerNS string) string {
	ret := fmt.Sprintf(`
provider "vault" {
  namespace = %q
}

resource "vault_namespace" "parent" {
  path                   = "%s"
}

resource "vault_namespace" "test" {
  path                   = %q
  namespace              = vault_namespace.parent.path
}
`, providerNS, parentNSPath, path)

	return ret
}

func testNamespaceCheckAttrs() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_namespace.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		return nil
	}
}

func testNamespaceDestroy(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

		namespaceRef, err := client.Logical().Read(fmt.Sprintf("%s/%s", consts.SysNamespaceRoot, path))
		if err != nil {
			return fmt.Errorf("error reading back configuration: %s", err)
		}
		if namespaceRef != nil {
			return fmt.Errorf("namespace still exists")
		}

		return nil
	}
}

func testNamespaceConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path                   = %q
}
`, path)
}

func testNestedNamespaces(ns string, count int) string {
	config := fmt.Sprintf(`
variable "child_prefix" {
  default = "child_"
}

variable "child_count" {
  default = %d
}

resource "vault_namespace" "parent" {
  path = "%s"
}

resource "vault_namespace" "child" {
  namespace = vault_namespace.parent.path
  count     = var.child_count
  path      = "${var.child_prefix}${count.index}"
}
`, count, ns)

	return config
}

func testNamespaceCustomMetadata(path string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "parent" {
  path            = %q
  custom_metadata = {
    foo = "abc",
    bar = "123"
  }
}
`, path)
}
