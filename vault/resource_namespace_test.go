// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
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
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testNamespaceDestroy(namespacePath),
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
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

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

func TestAccNamespace_customMetadataUpdate(t *testing.T) {
	namespacePath := acctest.RandomWithPrefix("tf-acc-test")
	resourceNameTest := "vault_namespace.test"
	resourceNameChild := "vault_namespace.child"
	childPath := "child"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion112)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testNamespaceDestroy(namespacePath),
		Steps: []resource.TestStep{
			{
				Config: testAccNamespaceConfig_metadata(namespacePath, `{ env = "dev", owner = "hashi", team = "CE" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameTest, consts.FieldPath, namespacePath),
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.%", "3"),
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.env", "dev"),
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.owner", "hashi"),
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.team", "CE"),
					testNamespaceCustomMetadataInVault("", namespacePath, map[string]string{
						"env": "dev", "owner": "hashi", "team": "CE",
					}),
				),
			},
			{
				ResourceName:      resourceNameTest,
				ImportState:       true,
				ImportStateVerify: true,
				// path_fq keeps the trailing slash from the import ID.
				ImportStateVerifyIgnore: []string{consts.FieldPathFQ},
			},
			{
				Config: testAccNamespaceConfig_metadata(namespacePath, `{ env = "dev", owner = "hashi" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.env", "dev"),
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.owner", "hashi"),
					resource.TestCheckNoResourceAttr(resourceNameTest, "custom_metadata.team"),
					testNamespaceCustomMetadataInVault("", namespacePath, map[string]string{
						"env": "dev", "owner": "hashi",
					}),
				),
			},
			{
				// Update, add and remove keys in a single apply.
				Config: testAccNamespaceConfig_metadata(namespacePath, `{ owner = "alice", region = "us-east" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.owner", "alice"),
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.region", "us-east"),
					resource.TestCheckNoResourceAttr(resourceNameTest, "custom_metadata.env"),
					testNamespaceCustomMetadataInVault("", namespacePath, map[string]string{
						"owner": "alice", "region": "us-east",
					}),
				),
			},
			{
				// Out-of-band key must be removed on the next apply.
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
					_, err := client.Logical().JSONMergePatch(context.Background(), consts.SysNamespaceRoot+namespacePath,
						map[string]interface{}{
							consts.FieldCustomMetadata: map[string]interface{}{"drift": "yes"},
						})
					if err != nil {
						t.Fatalf("failed to add out-of-band metadata: %s", err)
					}
				},
				Config: testAccNamespaceConfig_metadata(namespacePath, `{ owner = "alice", region = "us-east" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.%", "2"),
					resource.TestCheckNoResourceAttr(resourceNameTest, "custom_metadata.drift"),
					testNamespaceCustomMetadataInVault("", namespacePath, map[string]string{
						"owner": "alice", "region": "us-east",
					}),
				),
			},
			{
				Config: testAccNamespaceConfig_nestedMetadata(namespacePath, childPath, `{ app = "web", tier = "frontend" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameChild, "custom_metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceNameChild, "custom_metadata.app", "web"),
					resource.TestCheckResourceAttr(resourceNameChild, "custom_metadata.tier", "frontend"),
					testNamespaceCustomMetadataInVault(namespacePath, childPath, map[string]string{
						"app": "web", "tier": "frontend",
					}),
				),
			},
			{
				Config: testAccNamespaceConfig_nestedMetadata(namespacePath, childPath, `{ app = "web" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameChild, "custom_metadata.%", "1"),
					resource.TestCheckNoResourceAttr(resourceNameChild, "custom_metadata.tier"),
					testNamespaceCustomMetadataInVault(namespacePath, childPath, map[string]string{
						"app": "web",
					}),
				),
			},
			{
				Config: testAccNamespaceConfig_metadata(namespacePath, "{}"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.%", "0"),
					testNamespaceCustomMetadataInVault("", namespacePath, map[string]string{}),
				),
			},
			{
				Config: testAccNamespaceConfig_metadata(namespacePath, `{ env = "dev" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.%", "1"),
					testNamespaceCustomMetadataInVault("", namespacePath, map[string]string{
						"env": "dev",
					}),
				),
			},
			{
				Config: testAccNamespaceConfig_metadata(namespacePath, "null"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameTest, "custom_metadata.%", "0"),
					testNamespaceCustomMetadataInVault("", namespacePath, map[string]string{}),
				),
			},
		},
	})
}

// testNamespaceCustomMetadataInVault reads the namespace directly from Vault and
// asserts custom_metadata matches expected exactly.
func testNamespaceCustomMetadataInVault(parentNS, path string, expected map[string]string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := testProvider.Meta().(*provider.ProviderMeta).MustGetClient().Clone()
		if err != nil {
			return err
		}
		if parentNS != "" {
			ns := parentNS
			if base := client.Namespace(); base != "" {
				ns = base + "/" + parentNS
			}
			client.SetNamespace(ns)
		}

		resp, err := client.Logical().Read(consts.SysNamespaceRoot + path)
		if err != nil {
			return fmt.Errorf("error reading namespace %q: %w", path, err)
		}
		if resp == nil {
			return fmt.Errorf("namespace %q not found", path)
		}

		actual, _ := resp.Data[consts.FieldCustomMetadata].(map[string]interface{})
		if len(actual) != len(expected) {
			return fmt.Errorf("expected custom_metadata %v in Vault, got %v", expected, actual)
		}
		for k, v := range expected {
			if actual[k] != v {
				return fmt.Errorf("expected custom_metadata %v in Vault, got %v", expected, actual)
			}
		}

		return nil
	}
}

func testAccNamespaceConfig_metadata(path, metadata string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path            = %q
  custom_metadata = %s
}
`, path, metadata)
}

func testAccNamespaceConfig_nestedMetadata(path, childPath, childMetadata string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path            = %q
  custom_metadata = { owner = "alice", region = "us-east" }
}

resource "vault_namespace" "child" {
  namespace       = vault_namespace.test.path
  path            = %q
  custom_metadata = %s
}
`, path, childPath, childMetadata)
}
