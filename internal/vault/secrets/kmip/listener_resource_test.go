// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPListener_basic(t *testing.T) {
	acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("listener")
	resourceType := "vault_kmip_secret_listener"
	resourceName := resourceType + ".test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 2)
	if err != nil {
		t.Fatal(err)
	}

	addr1, addr2 := lns[0].Addr().String(), lns[1].Addr().String()

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPListener_initialConfig(path, name, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "test-ca"),
					resource.TestCheckResourceAttr(resourceName, "address", addr1),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.0", "localhost"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls12"),
					resource.TestCheckResourceAttr(resourceName, "also_use_legacy_ca", "false"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKMIPListenerImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
			},
			{
				Config: testKMIPListener_updateConfig(path, name, addr2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "test-ca"),
					resource.TestCheckResourceAttr(resourceName, "address", addr2),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.0", "localhost"),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.1", "example.com"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls13"),
					resource.TestCheckResourceAttr(resourceName, "also_use_legacy_ca", "true"),
				),
			},
		},
	})
}

func TestAccKMIPListener_remount(t *testing.T) {
	acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	remountPath := acctest.RandomWithPrefix("tf-test-kmip-updated")
	name := acctest.RandomWithPrefix("listener")
	resourceType := "vault_kmip_secret_listener"
	resourceName := resourceType + ".test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}

	addr1 := lns[0].Addr().String()

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPListener_initialConfig(path, name, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "test-ca"),
					resource.TestCheckResourceAttr(resourceName, "address", addr1),
				),
			},
			{
				Config: testKMIPListener_initialConfig(remountPath, name, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, remountPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "test-ca"),
					resource.TestCheckResourceAttr(resourceName, "address", addr1),
				),
			},
		},
	})
}

func TestAccKMIPListener_additionalClientCAs(t *testing.T) {
	acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("listener")
	resourceType := "vault_kmip_secret_listener"
	resourceName := resourceType + ".test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 2)
	if err != nil {
		t.Fatal(err)
	}

	addr1, addr2 := lns[0].Addr().String(), lns[1].Addr().String()

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPListener_additionalClientCAsConfig(path, name, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "test-ca"),
					resource.TestCheckResourceAttr(resourceName, "address", addr1),
					resource.TestCheckResourceAttr(resourceName, "additional_client_cas.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "additional_client_cas.0", "client-ca-1"),
					resource.TestCheckResourceAttr(resourceName, "additional_client_cas.1", "client-ca-2"),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.0", "localhost"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKMIPListenerImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
			},
			{
				Config: testKMIPListener_additionalClientCAsUpdateConfig(path, name, addr2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "test-ca"),
					resource.TestCheckResourceAttr(resourceName, "address", addr2),
					resource.TestCheckResourceAttr(resourceName, "additional_client_cas.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "additional_client_cas.0", "client-ca-1"),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.0", "localhost"),
				),
			},
		},
	})
}

func testAccKMIPListenerImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/listener/%s", rs.Primary.Attributes[consts.FieldPath], rs.Primary.Attributes[consts.FieldName]), nil
	}
}

func testKMIPListener_initialConfig(path, name, addr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
}

resource "vault_kmip_secret_ca_generated" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "test-ca"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_listener" "test" {
  path             = vault_kmip_secret_backend.test.path
  name             = "%s"
  ca               = vault_kmip_secret_ca_generated.test.name
  address          = "%s"
  server_hostnames = ["localhost"]
  tls_min_version  = "tls12"
}`, path, name, addr)
}

func testKMIPListener_updateConfig(path, name, addr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
}

resource "vault_kmip_secret_ca_generated" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "test-ca"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_listener" "test" {
  path               = vault_kmip_secret_backend.test.path
  name               = "%s"
  ca                 = vault_kmip_secret_ca_generated.test.name
  address            = "%s"
  server_hostnames   = ["localhost", "example.com"]
  tls_min_version    = "tls13"
  also_use_legacy_ca = true
}`, path, name, addr)
}

// Made with Bob

func testKMIPListener_additionalClientCAsConfig(path, name, addr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_generated" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "test-ca"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_ca_generated" "client1" {
  path     = vault_kmip_secret_backend.test.path
  name     = "client-ca-1"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_ca_generated" "client2" {
  path     = vault_kmip_secret_backend.test.path
  name     = "client-ca-2"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_listener" "test" {
  path                 = vault_kmip_secret_backend.test.path
  name                 = "%s"
  ca                   = vault_kmip_secret_ca_generated.test.name
  address              = "%s"
  server_hostnames     = ["localhost"]
  additional_client_cas = [
    vault_kmip_secret_ca_generated.client1.name,
    vault_kmip_secret_ca_generated.client2.name,
  ]
}`, path, name, addr)
}

func testKMIPListener_additionalClientCAsUpdateConfig(path, name, addr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_generated" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "test-ca"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_ca_generated" "client1" {
  path     = vault_kmip_secret_backend.test.path
  name     = "client-ca-1"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_ca_generated" "client2" {
  path     = vault_kmip_secret_backend.test.path
  name     = "client-ca-2"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_listener" "test" {
  path                 = vault_kmip_secret_backend.test.path
  name                 = "%s"
  ca                   = vault_kmip_secret_ca_generated.test.name
  address              = "%s"
  server_hostnames     = ["localhost"]
  additional_client_cas = [
    vault_kmip_secret_ca_generated.client1.name,
  ]
}`, path, name, addr)
}
