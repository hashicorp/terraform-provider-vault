package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataSourceGenericSecret(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceGenericSecret_config,
				Check:  testDataSourceGenericSecret_check,
			},
		},
	})
}

func TestV2Secret(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-acctest-kv/")
	path := acctest.RandomWithPrefix("foo")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testv2DataSourceGenericSecret_config(mount, path),
				Check:  testDataSourceGenericSecret_check,
			},
			{
				Config: testv2DataSourceGenericSecretUpdated_config(mount, path),
				Check:  testDataSourceGenericSecret_check,
			},
			{
				Config: testv2DataSourceGenericSecretUpdatedLatest_config(mount, path),
				Check:  testDataSourceGenericSecretUpdated_check,
			},
		},
	})
}

func testv2DataSourceGenericSecret_config(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv"
  description = "This is an example mount"
  options = {
    "version" = "2"
  }
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.test.path}/%s"
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}

data "vault_generic_secret" "test" {
    path = vault_generic_secret.test.path
    version = -1
}
`, mount, path)
}

func testv2DataSourceGenericSecretUpdated_config(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv"
  description = "This is an example mount"
  options = {
    "version" = "2"
  }
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.test.path}/%s"
    data_json = <<EOT
{
    "zip": "kablamo"
}
EOT
}

data "vault_generic_secret" "test" {
    path = vault_generic_secret.test.path
    version = 1
}
`, mount, path)
}

func testv2DataSourceGenericSecretUpdatedLatest_config(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv"
  description = "This is an example mount"
  options = {
    "version" = "2"
  }
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.test.path}/%s"
    data_json = <<EOT
{
    "zip": "kablamo"
}
EOT
}

data "vault_generic_secret" "test" {
    path = vault_generic_secret.test.path
    version = 0
}
`, mount, path)
}

var testDataSourceGenericSecret_config = `

resource "vault_mount" "v1" {
	  path = "secretsv1"
	  type = "kv"
	  options = {
		  version = "1"
	  }
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.v1.path}/foo"
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}

data "vault_generic_secret" "test" {
    path = vault_generic_secret.test.path
}

`

func testDataSourceGenericSecret_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_generic_secret.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	wantJson := `{"zip":"zap"}`
	if got, want := iState.Attributes["data_json"], wantJson; got != want {
		return fmt.Errorf("data_json contains %s; want %s", got, want)
	}

	if got, want := iState.Attributes["data.zip"], "zap"; got != want {
		return fmt.Errorf("data[\"zip\"] contains %s; want %s", got, want)
	}

	return nil
}

func testDataSourceGenericSecretUpdated_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_generic_secret.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	wantJson := `{"zip":"kablamo"}`
	if got, want := iState.Attributes["data_json"], wantJson; got != want {
		return fmt.Errorf("data_json contains %s; want %s", got, want)
	}

	if got, want := iState.Attributes["data.zip"], "kablamo"; got != want {
		return fmt.Errorf("data[\"zip\"] contains %s; want %s", got, want)
	}

	return nil
}
