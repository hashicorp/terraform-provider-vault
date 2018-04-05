package vault

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceConsulRole(t *testing.T) {
	path := acctest.RandomWithPrefix("consul/roles/test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testResourceConsulRole_initialConfig(path),
				Check:  testResourceConsulRole_initialCheck(path),
			},
			resource.TestStep{
				Config: testResourceConsulRole_updateConfig,
				Check:  testResourceConsulRole_updateCheck,
			},
		},
	})
}

func TestResourceConsulRole_deleted(t *testing.T) {
	path := acctest.RandomWithPrefix("consul/roles/test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testResourceConsulRole_initialConfig(path),
				Check:  testResourceConsulRole_initialCheck(path),
			},
			resource.TestStep{
				PreConfig: func() {
					client := testProvider.Meta().(*api.Client)
					_, err := client.Logical().Delete(path)
					if err != nil {
						t.Fatalf("unable to manually delete the consul role via the SDK: %s", err)
					}
				},
				Config: testResourceConsulRole_initialConfig(path),
				Check:  testResourceConsulRole_initialCheck(path),
			},
		},
	})
}

func testResourceConsulRole_initialConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_consul_role" "test" {
    name = "%s"
    policy = <<EOT
key "zip/zap" { policy = "read" }
EOT
}`, name)
}

func testResourceConsulRole_initialCheck(expectedName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_consul_role.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		name := instanceState.Attributes["name"]
		path := instanceState.ID
		constructedPath := "consul/roles/" + name

		if name != expectedName {
			return fmt.Errorf("unexpected policy name %q, expected %q", name, expectedName)
		}

		if path != constructedPath {
			return fmt.Errorf("id %q doesn't match path %q", path, instanceState.Attributes["name"])
		}

		client := testProvider.Meta().(*api.Client)
		role, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading back role: %s", err)
		}

		decodedPolicy, err := base64.StdEncoding.DecodeString(role.Data["policy"].(string))
		if err != nil {
			return fmt.Errorf("error base64 decoding role: %s", err)
		}

		if got, want := string(decodedPolicy[:]), "key \"zip/zap\" { policy = \"read\" }"; got != want {
			return fmt.Errorf("role data is %q; want %q", got, want)
		}

		return nil
	}
}

var testResourceConsulRole_updateConfig = `
resource "vault_consul_role" "test" {
    name = "%s"
    role = <<EOT
key "zip/zoop" { policy = "write" }
EOT
}
`

func testResourceConsulRole_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_consul_role.test"]
	instanceState := resourceState.Primary

	path := instanceState.ID

	client := testProvider.Meta().(*api.Client)
	role, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading back role: %s", err)
	}

	decodedPolicy, err := base64.StdEncoding.DecodeString(role.Data["policy"].(string))
	if err != nil {
		return fmt.Errorf("error base64 decoding role: %s", err)
	}

	if got, want := string(decodedPolicy[:]), "key \"zip/zoop\" { policy = \"write\" }"; got != want {
		return fmt.Errorf("role data is %q; want %q", got, want)
	}
	return nil
}
