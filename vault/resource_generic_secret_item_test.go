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

	if secret == nil {
		return nil
	}

	if got, want := secret.Data["foo"], "baz"; got != want {
		return fmt.Errorf("'foo' data is %q; want %q", got, want)
	}

	return nil
}
