// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceGenericSecret(t *testing.T) {
	var p *schema.Provider
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceGenericSecret_config,
				Check:  testDataSourceGenericSecret_check,
			},
		},
	})
}

func TestDataSourceGenericSecret_v2(t *testing.T) {
	var p *schema.Provider
	mount := acctest.RandomWithPrefix("tf-acctest-kv/")
	path := acctest.RandomWithPrefix("foo")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceV2Secret_config(mount, path),
				Check:  testDataSourceGenericSecret_check,
			},
			{
				Config: testDataSourceV2SecretUpdated_config(mount, path),
				Check:  testDataSourceGenericSecret_check,
			},
			{
				Config: testDataSourceV2SecretUpdatedLatest_config(mount, path),
				Check:  testDataSourceGenericSecretUpdated_check,
			},
		},
	})
}

func testDataSourceV2Secret_config(mount, path string) string {
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

func testDataSourceV2SecretUpdated_config(mount, path string) string {
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

func testDataSourceV2SecretUpdatedLatest_config(mount, path string) string {
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

	ts, ok := iState.Attributes["lease_start_time"]
	if !ok {
		return fmt.Errorf("lease_start_time not set")
	}

	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return fmt.Errorf("lease_start_time value %q is not in the expected format, err=%s", ts, err)
	}

	elapsed := time.Now().UTC().Unix() - t.Unix()
	// give a reasonable amount of buffer to allow for any system contention.
	maxElapsed := int64(30)
	if elapsed > maxElapsed {
		return fmt.Errorf("elapsed lease_start_time %ds exceeds maximum %ds", elapsed, maxElapsed)
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
