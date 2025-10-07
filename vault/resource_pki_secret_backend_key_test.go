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

type testPKIKeyStore struct {
	id string
}

func TestAccPKISecretBackendKey_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_key"
	resourceName := resourceType + ".test"

	keyName := acctest.RandomWithPrefix("tf-pki-key")
	updatedKeyName := acctest.RandomWithPrefix("tf-pki-key-updated")

	store := &testPKIKeyStore{}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendKey_basic(mount, keyName, "rsa", "2048"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "2048"),
					testCapturePKIKeyID(resourceName, store),
				),
			},
			// key name can be updated
			// test that updating name ensures the key ID is unchanged
			{
				Config: testAccPKISecretBackendKey_basic(mount, updatedKeyName, "rsa", "2048"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, updatedKeyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "rsa"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "2048"),
					// ensure that the Key ID is unchanged
					testPKIKeyUpdate(resourceName, store, true),
					testCapturePKIKeyID(resourceName, store),
				),
			},
			// any other updates trigger a force new
			// test that key ID is different (new key created)
			{
				Config: testAccPKISecretBackendKey_basic(mount, updatedKeyName, "ec", "224"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyName, updatedKeyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyBits, "224"),
					testPKIKeyUpdate(resourceName, store, false),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldType, consts.FieldKeyBits},
			},
		},
	})
}

func testAccPKISecretBackendKey_basic(path, keyName, keyType, keyBits string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_key" "test" {
  backend  = vault_mount.test.path
  type     = "exported"
  key_name = "%s"
  key_type = "%s"
  key_bits = "%s"
}`, path, keyName, keyType, keyBits)
}

func testCapturePKIKeyID(resourceName string, store *testPKIKeyStore) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		id, ok := rs.Primary.Attributes["key_id"]
		if !ok {
			return fmt.Errorf("key_id not found in state")
		}
		store.id = id

		return nil
	}
}

func testPKIKeyUpdate(resourceName string, store *testPKIKeyStore, expectedEqual bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if store.id == "" {
			return fmt.Errorf("id in %#v is empty", store)
		}

		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		id, ok := rs.Primary.Attributes["key_id"]
		if !ok {
			return fmt.Errorf("key_id not found in state")
		}

		if (store.id == id) != expectedEqual {
			return fmt.Errorf("expectedEqual=%v, got IDs %s and %s", expectedEqual, id, store.id)
		}

		return nil
	}
}
