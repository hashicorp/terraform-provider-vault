package vault

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestNamespace_basic(t *testing.T) {

	isEnterprise := os.Getenv("TF_ACC_ENTERPRISE")
	if isEnterprise == "" {
		t.Skip("TF_ACC_ENTERPRISE is not set, test is applicable only for Enterprise version of Vault")
	}

	namespacePath := acctest.RandomWithPrefix("test-namespace")
	childPath := acctest.RandomWithPrefix("child-namespace")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testNamespaceDestroy(namespacePath),
		Steps: []resource.TestStep{
			{
				Config: testNamespaceConfig(namespacePath),
				Check:  testNamespaceCheckAttrs(),
			},
			{
				Config:      testNamespaceConfig(namespacePath + "/"),
				Destroy:     false,
				ExpectError: regexp.MustCompile("Error: cannot write to a path ending in '/'"),
			},
			{
				Config: testNestedNamespaceConfig(namespacePath, childPath),
				Check:  testNestedNamespaceCheckAttrs(childPath),
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
		client := testProvider.Meta().(*api.Client)

		namespaceRef, err := client.Logical().Read(fmt.Sprintf("/sys/namespaces/%s", path))
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

func testNestedNamespaceConfig(parentPath, childPath string) string {
	return fmt.Sprintf(`
provider "vault" {
	namespace = %q
}

resource "vault_namespace" "test_child" {
	path = %q
}
`, parentPath, childPath)
}

func testNestedNamespaceCheckAttrs(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_namespace.test_child"]
		if resourceState == nil {
			return fmt.Errorf("child namespace resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("child namespace resource has no primary instance")
		}

		actualPath := instanceState.Attributes["path"]
		if actualPath != expectedPath {
			return fmt.Errorf("expected path to be %s, got %s", expectedPath, actualPath)
		}

		return nil
	}
}
