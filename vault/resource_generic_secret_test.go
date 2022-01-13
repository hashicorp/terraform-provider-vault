package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestResourceGenericSecret(t *testing.T) {
	mount := "secretsv1"
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(mount, name),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				Config: testResourceGenericSecret_updateConfig,
				Check:  testResourceGenericSecret_updateCheck,
			},
		},
	})
}

func TestResourceGenericSecret_deleted(t *testing.T) {
	mount := "secretsv1"
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(mount, path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*ProviderMeta).GetClient()
					_, err := client.Logical().Delete(path)
					if err != nil {
						t.Fatalf("unable to manually delete the secret via the SDK: %s", err)
					}
				},
				Config: testResourceGenericSecret_initialConfig(mount, path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
		},
	})
}

func TestResourceGenericSecret_deleteAllVersions(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv2/test")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAllVersionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig_v2(path, false),
				Check:  testResourceGenericSecret_initialCheck_v2(path, "zap", 1),
			},
			{
				Config: testResourceGenericSecret_initialConfig_v2(path, true),
				Check:  testResourceGenericSecret_initialCheck_v2(path, "zoop", 2),
			},
		},
	})
}

func testResourceGenericSecret_initialConfig(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "foo" {
    path = "foo"
}

resource "vault_mount" "v1" {
	path = "%s"
    namespace = vault_namespace.foo.path
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
    namespace = vault_mount.v1.namespace
    path = "${vault_mount.v1.path}/%s"
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}`, mount, path)
}

func testResourceGenericSecret_initialConfig_v2(path string, isUpdate bool) string {
	result := fmt.Sprintf(`
resource "vault_mount" "v2" {
	path = "secretsv2"
	type = "kv"
	options = {
		version = "2"
	}
}

`)
	if !isUpdate {
		result += fmt.Sprintf(`
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
	} else {
		result += fmt.Sprintf(`
resource "vault_generic_secret" "test" {
	depends_on = ["vault_mount.v2"]
	path = "%s"
	delete_all_versions = true
	data_json = <<EOT
{
	"zip": "zoop"
}
EOT
}`, path)
	}

	return result
}

func testResourceGenericSecret_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_generic_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		state := resourceState.Primary
		if state == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := state.ID

		if path != state.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}
		if path != expectedPath {
			return fmt.Errorf("unexpected secret path")
		}

		client, err := GetClientForInstanceState(state, testProvider.Meta())
		if err != nil {
			return err
		}

		secret, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading back secret: %s", err)
		}

		data := secret.Data
		// Test the JSON
		if got, want := data["zip"], "zap"; got != want {
			return fmt.Errorf("'zip' data is %q; want %q", got, want)
		}

		// Test the map
		if got, want := state.Attributes["data.zip"], "zap"; got != want {
			return fmt.Errorf("data[\"zip\"] contains %s; want %s", got, want)
		}

		return nil
	}
}

func testResourceGenericSecret_initialCheck_v2(expectedPath string, wantValue string, versionCount int) resource.TestCheckFunc {
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

		client := testProvider.Meta().(*ProviderMeta).GetClient()

		// Checking KV-V2 Secrets
		resp, err := client.Logical().List("secretsv2/metadata")
		if err != nil {
			return fmt.Errorf("unable to list secrets metadata: %s", err)
		}

		if resp == nil {
			return fmt.Errorf("expected kv-v2 secrets, got nil")
		}
		keys := resp.Data["keys"].([]interface{})
		secret, err := client.Logical().Read(fmt.Sprintf("secretsv2/data/%s", keys[0]))
		if secret == nil {
			return fmt.Errorf("no secret found at secretsv2/data/%s", keys[0])
		}

		data := secret.Data["data"].(map[string]interface{})

		// Confirm number of versions
		err = testResourceGenericSecret_checkVersions(client, keys[0].(string), versionCount)
		if err != nil {
			return fmt.Errorf("Version error: %s", err)
		}

		// Test the JSON
		if got := data["zip"]; got != wantValue {
			return fmt.Errorf("'zip' data is %q; want %q", got, wantValue)
		}

		// Test the map
		if got := instanceState.Attributes["data.zip"]; got != wantValue {
			return fmt.Errorf("data[\"zip\"] contains %s; want %s", got, wantValue)
		}
		return nil
	}
}

func testResourceGenericSecret_checkVersions(client *api.Client, keyName string, versionCount int) error {
	resp, err := client.Logical().Read(fmt.Sprintf("secretsv2/metadata/%s", keyName))
	if err != nil {
		return fmt.Errorf("unable to read secrets metadata at path secretsv2/metadata/%s: %s", keyName, err)
	}

	versions := resp.Data["versions"].(map[string]interface{})

	if len(versions) != versionCount {
		return fmt.Errorf("Expected %d versions, got %d", versionCount, len(versions))
	}

	return nil
}

func testAllVersionDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*ProviderMeta).GetClient()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_generic_secret" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for generic secret %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("generic secret %q still exists", rs.Primary.ID)
		}
	}
	return nil
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

	client := testProvider.Meta().(*ProviderMeta).GetClient()
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading back secret: %s", err)
	}

	if got, want := secret.Data["zip"], "zoop"; got != want {
		return fmt.Errorf("'zip' data is %q; want %q", got, want)
	}

	return nil
}
