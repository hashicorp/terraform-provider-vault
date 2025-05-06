// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceNomadAccessCredentialsClientBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := testutil.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNomadAccessCredentialsConfig(backend, address, token, "test"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_token.token", "secret_id"),
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_token.token", "accessor_id"),
				),
			},
		},
	})
}

func TestAccDataSourceNomadAccessCredentialsManagementBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := testutil.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNomadAccessCredentialsManagementConfig(backend, address, token, "test"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_token.token", "secret_id"),
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_token.token", "accessor_id"),
				),
			},
		},
	})
}

func testAccDataSourceNomadAccessCredentialsConfig(backend, address, token, role string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	address = "%s"
	token = "%s"
}

resource "vault_nomad_secret_role" "test" {
    backend = vault_nomad_secret_backend.config.backend
	role = "%s"
	policies = ["reaodnly"]
}

data "vault_nomad_access_token" "token" {
  backend = vault_nomad_secret_backend.config.backend
  role    = vault_nomad_secret_role.test.role
}
`, backend, address, token, role)
}

func testAccDataSourceNomadAccessCredentialsManagementConfig(backend, address, token, role string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	address = "%s"
	token = "%s"
}

resource "vault_nomad_secret_role" "test" {
    backend = vault_nomad_secret_backend.config.backend
	role = "%s"
	type = "management"
}

data "vault_nomad_access_token" "token" {
  backend = vault_nomad_secret_backend.config.backend
  role    = vault_nomad_secret_role.test.role
}
`, backend, address, token, role)
}
