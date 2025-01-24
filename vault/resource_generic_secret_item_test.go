// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestResourceGenericSecretItem(t *testing.T) {
	mount := acctest.RandomWithPrefix("secretsv1")
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resourceName := "vault_generic_secret_item.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecretItem_initialConfig(mount, name),
				Check:  testResourceGenericSecretItem_initialCheck(path),
			},
			{
				Config: testResourceGenericSecretItem_updateConfig(mount, name),
				Check:  testResourceGenericSecretItem_updateCheck,
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
		},
	})
}

func TestResourceGenericSecretItem_deleted(t *testing.T) {
	resourceName := "vault_generic_secret_item.test"

	mount := acctest.RandomWithPrefix("secretsv1")
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecretItem_initialConfig(mount, name),
				Check:  testResourceGenericSecretItem_initialCheck(path),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					_, err := client.Logical().Delete(path)
					if err != nil {
						t.Fatalf("unable to manually delete the secret via the SDK: %s", err)
					}
				},
				Config: testResourceGenericSecretItem_initialConfig(mount, name),
				Check:  testResourceGenericSecretItem_initialCheck(path),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
		},
	})
}

func TestResourceGenericSecretItem_deleteAllVersions(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv2/test")
	resourceName := "vault_generic_secret_item.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAllVersionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecretItem_initialConfig_v2(path, false),
				Check:  testResourceGenericSecretItem_initialCheck_v2(path, "zap", 1),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
			{
				Config: testResourceGenericSecretItem_initialConfig_v2(path, true),
				Check:  testResourceGenericSecretItem_initialCheck_v2(path, "zoop", 2),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
		},
	})
}

func testResourceGenericSecretItem_initialConfig(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "v1" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret_item" "test" {
    path = "${vault_mount.v1.path}/%s"
    key  = "foo"
	value = "bar"
}`, mount, name)
}

func testResourceGenericSecretItem_updateConfig(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "v1" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret_item" "test" {
    path  = "${vault_mount.v1.path}/%s"
	key   = "foo"
	value = "baz"
}
`, mount, name)
}

func testResourceGenericSecretItem_initialConfig_v2(path string, isUpdate bool) string {
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
resource "vault_generic_secret_item" "test" {
	depends_on = ["vault_mount.v2"]

	path  = "%s"
	key   = "foo"
	value = "bar"
EOT
}`, path)
	} else {
		result += fmt.Sprintf(`
resource "vault_generic_secret_item" "test" {
	depends_on = ["vault_mount.v2"]

	path  = "%s"
	key   = "foo"
	value = "baz"
}`, path)
	}

	return result
}

func testResourceGenericSecretItem_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_generic_secret_item.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		state := resourceState.Primary
		if state == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		key := state.ID
		path := state.Attributes["path"]

		if key != state.Attributes["key"] {
			return fmt.Errorf("id doesn't match key")
		}
		if path != expectedPath {
			return fmt.Errorf("unexpected secret path")
		}

		client, err := provider.GetClient(state, testProvider.Meta())
		if err != nil {
			return err
		}

		secret, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading back secret: %s", err)
		}

		if got, want := secret.Data["foo"], "bar"; got != want {
			return fmt.Errorf("'foo' data is %q; want %q", got, want)
		}

		return nil
	}
}

func testResourceGenericSecretItem_initialCheck_v2(expectedPath string, wantValue string, versionCount int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_generic_secret_item.test"]
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

		client, e := provider.GetClient(instanceState, testProvider.Meta())
		if e != nil {
			return e
		}

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

func testResourceGenericSecretItem_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_generic_secret_item.test"]
	state := resourceState.Primary

	path := state.ID

	client, err := provider.GetClient(state, testProvider.Meta())
	if err != nil {
		return err
	}

	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading back secret: %s", err)
	}

	if got, want := secret.Data["foo"], "baz"; got != want {
		return fmt.Errorf("'foo' data is %q; want %q", got, want)
	}

	return nil
}
