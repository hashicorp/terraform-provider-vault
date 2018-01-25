package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourcePkiGenerate(t *testing.T) {
	path := "example-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourcePkiMount_initialConfig(path, "intermediate", "example.com", ""),
				Check:  testResourcePkiMount_initialCheck(path, "intermediate", "example.com", ""),
			},
			{
				Config: testResourcePkiMount_initialConfig(path, "root", "example.com", ""),
				Check:  testResourcePkiMount_initialCheck(path, "root", "example.com", ""),
			},
			{
				Config: testResourcePkiMount_initialConfig(path, "root", "example.com", fmt.Sprintf("secret/%s", path)),
				Check:  testResourcePkiMount_initialCheck(path, "root", "example.com", fmt.Sprintf("secret/%s", path)),
			},
		},
	})
}

func testResourcePkiMount_initialConfig(path, caType, caCommonName, secretPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "pki" {
	path = "%s"
	type = "pki"
	description = "test pki backend"
}

resource "vault_pki_generate" "cacert" {
	backend = "${vault_mount.pki.path}"
	type = "%s"
	common_name = "%s"
	secret_path = "%s"
}
`, path, caType, caCommonName, secretPath)
}

func testResourcePkiMount_initialCheck(expectedPath, caType, commonName, secretPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_pki_generate.cacert"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		if actual := instanceState.Attributes["type"]; caType != actual {
			return fmt.Errorf("type %q doesn't match type %q", caType, actual)
		}

		if actual := instanceState.Attributes["common_name"]; commonName != actual {
			return fmt.Errorf("common_name %q doesn't match common_name %q: %v", commonName, actual, instanceState.Attributes)
		}

		if secretPath != "" {
			secret, err := findSecret(secretPath)
			if err != nil {
				return fmt.Errorf("secret not found at secret_path %s: %s", secretPath, err)
			}

			fields := []string{"certificate", "private_key"}
			for _, field := range fields {
				if _, ok := secret.Data[field]; !ok {
					return fmt.Errorf("expected secret at secret_path to have field %s", field)
				}
			}
		}

		return nil
	}
}

func findSecret(path string) (*api.Secret, error) {
	client := testProvider.Meta().(*api.Client)

	return client.Logical().Read(path)
}
