// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestResourceGenericSecret(t *testing.T) {
	mount := acctest.RandomWithPrefix("secretsv1")
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resourceName := "vault_generic_secret.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(mount, name),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				Config: testResourceGenericSecret_updateConfig(mount, name),
				Check:  testResourceGenericSecret_updateCheck,
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
		},
	})
}

func TestResourceGenericSecretNS(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")
	mount := acctest.RandomWithPrefix("secretsv1")
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resourceName := "vault_generic_secret.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfigNS(ns, mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					testResourceGenericSecret_initialCheck(path),
				),
			},
			{
				// unfortunately two steps are needed when testing import,
				// since the tf-plugin-sdk does not allow for specifying environment variables :(
				// neither does have any support for generic post-step functions.
				// It is possible that this will cause issues if we ever want to support parallel tests.
				// We would have to update the SDK to suport specifying extra env vars by step.
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, ns)
				},
				ImportState:      true,
				ResourceName:     resourceName,
				ImportStateCheck: testutil.GetNamespaceImportStateCheck(ns),
			},
			{
				// needed for the import step above :(
				Config: testResourceGenericSecret_initialConfigNS(ns, mount, name),
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
				PlanOnly: true,
			},
			{
				Config: testResourceGenericSecret_updateConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(resourceName, "namespace"),
					testResourceGenericSecret_updateCheck,
				),
			},
		},
	})
}

func TestResourceGenericSecret_deleted(t *testing.T) {
	resourceName := "vault_generic_secret.test"

	mount := acctest.RandomWithPrefix("secretsv1")
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(mount, name),
				Check:  testResourceGenericSecret_initialCheck(path),
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
				Config: testResourceGenericSecret_initialConfig(mount, name),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
		},
	})
}

func TestResourceGenericSecret_skip_on_destroy_true(t *testing.T) {
	resourceName := "vault_generic_secret.test"

	fmt.Println(testResourceGenericSecret_initialConfig_skip_destroy("", "", true))

	mount := acctest.RandomWithPrefix("secretsv1")
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig_skip_destroy(mount, name, true),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

					_, err := client.Logical().Delete(path)
					if err != nil {
						t.Fatalf("unable to manually delete the secret via the SDK: %s", err)
					}
				},
				Config: testResourceGenericSecret_initialConfig_skip_destroy(mount, name, true),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
		},
	})
}

func TestResourceGenericSecret_deleteAllVersions(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv2/test")
	resourceName := "vault_generic_secret.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAllVersionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig_v2(path, false),
				Check:  testResourceGenericSecret_initialCheck_v2(path, "zap", 1),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
			{
				Config: testResourceGenericSecret_initialConfig_v2(path, true),
				Check:  testResourceGenericSecret_initialCheck_v2(path, "zoop", 2),
			},
			{
				ImportState:  true,
				ResourceName: resourceName,
			},
		},
	})
}

func testResourceGenericSecret_initialConfig(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "v1" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.v1.path}/%s"
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}`, mount, name)
}

func testResourceGenericSecret_initialConfig_skip_destroy(mount, name string, skip_destroy bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "v1" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.v1.path}/%s"
	skip_destroy = %v
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}`, mount, name, skip_destroy)
}

func testResourceGenericSecret_updateConfig(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "v1" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.v1.path}/%s"
    data_json = <<EOT
{
    "zip": "zoop"
}
EOT
}
`, mount, name)
}

func testResourceGenericSecret_initialConfigNS(ns, mount, name string) string {
	result := fmt.Sprintf(`
resource "vault_namespace" "ns1" {
    path = "%s"
}

resource "vault_mount" "v1" {
    namespace = vault_namespace.ns1.path
	path = "%s"
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
}`, ns, mount, name)

	return result
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

		client, err := provider.GetClient(state, testProvider.Meta())
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
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_generic_secret" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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

func testResourceGenericSecret_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_generic_secret.test"]
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

	if got, want := secret.Data["zip"], "zoop"; got != want {
		return fmt.Errorf("'zip' data is %q; want %q", got, want)
	}

	return nil
}
