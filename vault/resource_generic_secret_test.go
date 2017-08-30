package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"

	"github.com/hashicorp/vault/api"
)

func TestResourceGenericSecret(t *testing.T) {
	path := acctest.RandomWithPrefix("secret/test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			resource.TestStep{
				Config: testResourceGenericSecret_updateConfig,
				Check:  testResourceGenericSecret_updateCheck,
			},
		},
	})
}

func testResourceGenericSecret_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_generic_secret" "test" {
    path = "%s"
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}`, path)
}

func testResourceGenericSecret_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_generic_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}
		if path != expectedPath {
			return fmt.Errorf("unexpected secret path")
		}

		client := testProvider.Meta().(*api.Client)
		secret, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading back secret: %s", err)
		}

		if got, want := secret.Data["zip"], "zap"; got != want {
			return fmt.Errorf("'zip' data is %q; want %q", got, want)
		}

		return nil
	}
}

var testResourceGenericSecret_updateConfig = `

resource "vault_generic_secret" "test" {
    path = "secret/foo"
    disable_read = false
    data_json = <<EOT
{
    "zip": "zoop"
}
EOT
}

`

func testResourceGenericSecret_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_generic_secret.test"]
	instanceState := resourceState.Primary

	path := instanceState.ID

	client := testProvider.Meta().(*api.Client)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading back secret: %s", err)
	}

	if got, want := secret.Data["zip"], "zoop"; got != want {
		return fmt.Errorf("'zip' data is %q; want %q", got, want)
	}

	return nil
}
