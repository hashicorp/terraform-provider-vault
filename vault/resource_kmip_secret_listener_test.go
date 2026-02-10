// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPSecretListener_basic(t *testing.T) {
	testutil.SkipTestAccEnt(t)

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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		CheckDestroy:             testKMIPSecretListenerCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretListener_initialConfig(path, name, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "default"),
					resource.TestCheckResourceAttr(resourceName, "address", addr1),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "server_hostnames.*", "localhost"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls12"),
					resource.TestCheckResourceAttr(resourceName, "also_use_legacy_ca", "false"),
				),
			},
			{
				Config: testKMIPSecretListener_updateConfig(path, name, addr2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "default"),
					resource.TestCheckResourceAttr(resourceName, "address", addr2),
					resource.TestCheckResourceAttr(resourceName, "server_hostnames.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "server_hostnames.*", "localhost"),
					resource.TestCheckTypeSetElemAttr(resourceName, "server_hostnames.*", "example.com"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls13"),
					resource.TestCheckResourceAttr(resourceName, "also_use_legacy_ca", "true"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccKMIPSecretListener_remount(t *testing.T) {
	testutil.SkipTestAccEnt(t)

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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		CheckDestroy:             testKMIPSecretListenerCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretListener_initialConfig(path, name, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "default"),
					resource.TestCheckResourceAttr(resourceName, "address", addr1),
				),
			},
			{
				Config: testKMIPSecretListener_initialConfig(remountPath, name, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, remountPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "ca", "default"),
					resource.TestCheckResourceAttr(resourceName, "address", addr1),
				),
			},
		},
	})
}

func testKMIPSecretListenerCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kmip_secret_listener" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for KMIP listener %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("KMIP listener %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testKMIPSecretListener_initialConfig(path, name, addr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
  description                  = "test description"
  listen_addrs                 = ["127.0.0.1:5696"]
  server_hostnames             = ["localhost"]
  tls_ca_key_type              = "ec"
  tls_ca_key_bits              = 256
  default_tls_client_key_type  = "ec"
  default_tls_client_key_bits  = 256
  default_tls_client_ttl       = 86400
}

resource "vault_kmip_secret_listener" "test" {
  path             = vault_kmip_secret_backend.test.path
  name             = "%s"
  ca               = "default"
  address          = "%s"
  server_hostnames = ["localhost"]
  tls_min_version  = "tls12"
}`, path, name, addr)
}

func testKMIPSecretListener_updateConfig(path, name, addr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
  description                  = "test description"
  listen_addrs                 = ["127.0.0.1:5696"]
  server_hostnames             = ["localhost"]
  tls_ca_key_type              = "ec"
  tls_ca_key_bits              = 256
  default_tls_client_key_type  = "ec"
  default_tls_client_key_bits  = 256
  default_tls_client_ttl       = 86400
}

resource "vault_kmip_secret_listener" "test" {
  path               = vault_kmip_secret_backend.test.path
  name               = "%s"
  ca                 = "default"
  address            = "%s"
  server_hostnames   = ["localhost", "example.com"]
  tls_min_version    = "tls13"
  also_use_legacy_ca = true
}`, path, name, addr)
}

// Made with Bob
