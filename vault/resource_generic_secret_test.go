package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceGenericSecret(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv1/test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path, false),
			},
			{
				Config: testResourceGenericSecret_updateConfig,
				Check:  testResourceGenericSecret_updateCheck,
			},
		},
	})
}

func TestResourceGenericSecret_deleted(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv1/test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path, false),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*api.Client)
					_, err := client.Logical().Delete(path)
					if err != nil {
						t.Fatalf("unable to manually delete the secret via the SDK: %s", err)
					}
				},
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path, false),
			},
		},
	})
}

func TestResourceGenericSecret_deleteAllVersions(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv2/test")
	pathMetadata := "secretsv2/metadata/test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig_v2(path),
				Check:  testResourceGenericSecret_initialCheck(path, true),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*api.Client)
					_, err := client.Logical().Delete(pathMetadata)
					if err != nil {
						t.Fatalf("unable to manually delete key metadata: %s", err)
					}
				},
				Config: testResourceGenericSecret_initialConfig_v2(path),
				Check:  testResourceGenericSecret_initialCheck(path, true),
			},
		},
	})
}

func testResourceGenericSecret_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "v1" {
	path = "secretsv1"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
    depends_on = ["vault_mount.v1"]
    path = "%s"
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}`, path)
}

func testResourceGenericSecret_initialConfig_v2(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "v2" {
	path = "secretsv2"
	type = "kv"
	options = {
		version = "2"
	}
}
resource "vault_generic_secret" "test" {
    depends_on = ["vault_mount.v2"]
	path = "%s"
	delete_all_versions = true
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}`, path)
}

func testResourceGenericSecret_initialCheck(expectedPath string, isV2 bool) resource.TestCheckFunc {
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
		var secret *api.Secret
		var data map[string]interface{}
		if isV2 {
			resp, err := client.Logical().List("secretsv2/metadata")
			if err != nil {
				return fmt.Errorf("unable to list secrets metadata: %s", err)
			}

			if resp == nil {
				return fmt.Errorf("expected kv-v2 secrets, got nil")
			}
			keys := resp.Data["keys"].([]interface{})
			secret, err = client.Logical().Read(fmt.Sprintf("secretsv2/data/%s", keys[0]))
			if secret == nil {
				return fmt.Errorf("no secret found at secretsv2/data/%s", keys[0])
			}

			data = secret.Data["data"].(map[string]interface{})
		} else {
			var err error
			secret, err = client.Logical().Read(path)
			if err != nil {
				return fmt.Errorf("error reading back secret: %s", err)
			}

			data = secret.Data
		}

		// Test the JSON
		if got, want := data["zip"], "zap"; got != want {
			return fmt.Errorf("'zip' data is %q; want %q", got, want)
		}

		// Test the map
		if got, want := instanceState.Attributes["data.zip"], "zap"; got != want {
			return fmt.Errorf("data[\"zip\"] contains %s; want %s", got, want)
		}

		return nil
	}
}

var testResourceGenericSecret_updateConfig = `

resource "vault_mount" "v1" {
	path = "secretsv1"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.v1.path}/foo"
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
