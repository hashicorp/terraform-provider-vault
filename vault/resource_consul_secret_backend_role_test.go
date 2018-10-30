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

func TestResourceConsulSecretBackendRole(t *testing.T) {
	path := acctest.RandomWithPrefix("test")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceConsulSecretBackendRole_initialConfig(path),
				Check:  testResourceConsulSecretBackendRole_initialCheck(path),
			},
			{
				Config: testResourceConsulSecretBackendRole_updateConfig,
				Check:  testResourceConsulSecretBackendRole_updateCheck,
			},
		},
	})
}

func TestResourceConsulSecretBackendRole_deleted(t *testing.T) {
	path := acctest.RandomWithPrefix("test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceConsulSecretBackendRole_initialConfig(path),
				Check:  testResourceConsulSecretBackendRole_initialCheck(path),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*api.Client)
					_, err := client.Logical().Delete("consul/roles/" + path)
					if err != nil {
						t.Fatalf("unable to manually delete the consul role via the SDK: %s", err)
					}
				},
				Config: testResourceConsulSecretBackendRole_initialConfig(path),
				Check:  testResourceConsulSecretBackendRole_initialCheck(path),
			},
		},
	})
}

func testResourceConsulSecretBackendRole_initialConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend_role" "test" {
    name = "%s"
    policy = <<EOT
key "zip/zap" { policy = "read" }
EOT
}`, name)
}

func testResourceConsulSecretBackendRole_initialCheck(expectedName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_consul_secret_backend_role.test"]
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

		if got, want := string(decodedPolicy[:]), "key \"zip/zap\" { policy = \"read\" }\n"; got != want {
			return fmt.Errorf("role data is %q; want %q", got, want)
		}

		return nil
	}
}

var testResourceConsulSecretBackendRole_updateConfig = `
resource "vault_consul_secret_backend_role" "test" {
    name = "test"
    policy = <<EOT
key "zip/zoop" { policy = "write" }
EOT
}
`

func testResourceConsulSecretBackendRole_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_consul_secret_backend_role.test"]
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

	if got, want := string(decodedPolicy[:]), "key \"zip/zoop\" { policy = \"write\" }\n"; got != want {
		return fmt.Errorf("role data is %q; want %q", got, want)
	}
	return nil
}
