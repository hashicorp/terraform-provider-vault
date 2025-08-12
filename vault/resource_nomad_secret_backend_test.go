// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccNomadSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	// TODO: test environment should exist in CI
	address, token := testutil.GetTestNomadCreds(t)

	resourceType := "vault_nomad_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories:  testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                  func() { testutil.TestAccPreCheck(t) },
		PreventPostDestroyRefresh: true,
		CheckDestroy:              testCheckMountDestroyed(resourceType, consts.MountTypeNomad, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendConfig(backend, address, token, 60, 30, 3600, 7200),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "address", address),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "60"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "30"),
				),
			},
			{
				Config: testNomadSecretBackendConfig(backend, "foobar", token, 90, 60, 7200, 14400),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "14400"),
					resource.TestCheckResourceAttr(resourceName, "address", "foobar"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "90"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "60"),
				),
			},
			{
				Config: testNomadSecretBackendConfig(backend, "foobar", token, 0, 0, -1, -1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "-1"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "-1"),
					resource.TestCheckResourceAttr(resourceName, "address", "foobar"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "0"),
				),
			},
		},
	})
}

func TestNomadSecretBackend_remount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	updatedBackend := acctest.RandomWithPrefix("tf-test-nomad-updated")

	resourceName := "vault_nomad_secret_backend.test"
	address, token := testutil.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendConfig(backend, address, token, 60, 30, 3600, 7200),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "address", address),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "60"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "30"),
				),
			},
			{
				Config: testNomadSecretBackendConfig(updatedBackend, address, token, 60, 30, 3600, 7200),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", updatedBackend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "address", address),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "60"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "30"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "description", "token", "disable_remount"),
		},
	})
}

func testNomadSecretBackendConfig(backend, address, token string, maxTTL, ttl, defaultLease, maxLease int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
	backend = "%s"
	description = "test description"
	address = "%s"
	token = "%s"
	max_ttl = "%d"
	ttl = "%d"
	default_lease_ttl_seconds = "%d"
	max_lease_ttl_seconds = "%d"
}
`, backend, address, token, maxTTL, ttl, defaultLease, maxLease)
}
