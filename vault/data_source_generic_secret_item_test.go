// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceGenericSecretItem(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceGenericSecretItem_config,
				Check:  testDataSourceGenericSecretItem_check,
			},
		},
	})
}

func TestDataSourceGenericSecretItem_v2(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-acctest-kv/")
	path := acctest.RandomWithPrefix("foo")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceV2SecretItem_config(mount, path),
				Check:  testDataSourceGenericSecretItem_check,
			},
			{
				Config: testDataSourceV2SecretItemUpdated_config(mount, path),
				Check:  testDataSourceGenericSecretItemUpdated_check,
			},
		},
	})
}

func testDataSourceV2SecretItem_config(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv"
  description = "This is an example mount"
  options = {
    "version" = "2"
  }
}

resource "vault_generic_secret_item" "test" {
    path  = "${vault_mount.test.path}/%s"
    key   = "foo"
	value = "bar"
}

data "vault_generic_secret_item" "test" {
    path = vault_generic_secret_item.test.path
	key = "foo"
}
`, mount, path)
}

func testDataSourceV2SecretItemUpdated_config(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv"
  description = "This is an example mount"
  options = {
    "version" = "2"
  }
}

resource "vault_generic_secret_item" "test" {
    path  = "${vault_mount.test.path}/%s"
    key   = "foo"
	value = "baz"
}

data "vault_generic_secret_item" "test" {
    path = vault_generic_secret_item.test.path
    key  = "foo"
}
`, mount, path)
}

var testDataSourceGenericSecretItem_config = `

resource "vault_mount" "v1" {
	  path = "secretsv1"
	  type = "kv"
	  options = {
		  version = "1"
	  }
}

resource "vault_generic_secret_item" "test" {
    path  = "${vault_mount.v1.path}/foo"
	key   = "foo"
	value = "bar"
}

data "vault_generic_secret_item" "test" {
    path = vault_generic_secret_item.test.path
	key  = "foo"
}

`

func testDataSourceGenericSecretItem_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_generic_secret_item.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary

	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	wantKey := "foo"
	if got, want := iState.Attributes["key"], wantKey; got != want {
		return fmt.Errorf("key contains %s; want %s", got, want)
	}

	wantVal := "bar"
	if got, want := iState.Attributes["value"], wantVal; got != want {
		return fmt.Errorf("value contains %s; want %s", got, want)
	}

	return nil
}

func testDataSourceGenericSecretItemUpdated_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_generic_secret_item.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	wantKey := "foo"
	if got, want := iState.Attributes["key"], wantKey; got != want {
		return fmt.Errorf("key contains %s; want %s", got, want)
	}

	wantVal := "baz"
	if got, want := iState.Attributes["value"], wantVal; got != want {
		return fmt.Errorf("value contains %s; want %s", got, want)
	}

	return nil
}
