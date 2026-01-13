// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPSecretRole_basic(t *testing.T) {
	acctestutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	resourceType := "vault_kmip_secret_role"
	resourceName := resourceType + ".test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	addr1 := lns[0].Addr().String()

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeKMIP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretRole_initialConfig(path, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRevoke, "false"),
				),
			},
			{
				Config: testKMIPSecretRole_updatedConfig(path, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyType, "rsa"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyBits, "4096"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributeList, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDestroy, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRevoke, "false"),
				),
			},
		},
	})
}

func TestAccKMIPSecretRole_remount(t *testing.T) {
	acctestutil.SkipTestAccEnt(t)

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	addr1 := lns[0].Addr().String()

	path := acctest.RandomWithPrefix("tf-test-kmip")
	remountPath := acctest.RandomWithPrefix("tf-test-kmip-remount")
	resourceType := "vault_kmip_secret_role"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeKMIP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretRole_initialConfig(path, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRevoke, "false"),
				),
			},
			{
				Config: testKMIPSecretRole_initialConfig(remountPath, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, remountPath),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, fieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRevoke, "false"),
				),
			},
		},
	})
}

func TestAccKMIPSecretRole_newOperations(t *testing.T) {
	acctestutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip-ops")
	resourceType := "vault_kmip_secret_role"
	resourceName := resourceType + ".test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	addr1 := lns[0].Addr().String()

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeKMIP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretRole_newOperationsConfig(path, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					// New operation fields
					resource.TestCheckResourceAttr(resourceName, fieldOperationImport, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationQuery, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationEncrypt, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDecrypt, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationCreateKeyPair, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationDeleteAttribute, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRNGRetrieve, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationMAC, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationSignatureVerify, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationSign, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRNGSeed, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationModifyAttribute, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationMACVerify, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationRekeyKeyPair, "true"),
					// Existing operations should be false
					resource.TestCheckResourceAttr(resourceName, fieldOperationActivate, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationGet, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldOperationNone, "false"),
				),
			},
		},
	})
}

func testKMIPSecretRole_initialConfig(path string, listenAddr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "kmip" {
  path = "%s"
  listen_addrs = ["%s"]
  description = "test description"
}

resource "vault_kmip_secret_scope" "scope-1" {
    path = vault_kmip_secret_backend.kmip.path
    scope = "scope-1"
}

resource "vault_kmip_secret_role" "test" {
    path = vault_kmip_secret_scope.scope-1.path
    scope = "scope-1"
    role = "test"
	tls_client_key_type = "ec"
 	tls_client_key_bits = 256
	operation_activate = true
    operation_get = true
    operation_get_attributes = true
}
`, path, listenAddr)
}

func testKMIPSecretRole_updatedConfig(path string, listenAddr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "kmip" {
  path = "%s"
  listen_addrs = ["%s"]
  description = "test description"
}

resource "vault_kmip_secret_scope" "scope-1" {
    path = vault_kmip_secret_backend.kmip.path
    scope = "scope-1"
}

resource "vault_kmip_secret_role" "test" {
    path = vault_kmip_secret_scope.scope-1.path
    scope = "scope-1"
    role = "test"
	tls_client_key_type = "rsa"
 	tls_client_key_bits = 4096
	operation_activate = true
    operation_get = true
    operation_get_attributes = true
	operation_get_attribute_list = true
	operation_create = true
	operation_destroy = true
}
`, path, listenAddr)
}

func testKMIPSecretRole_newOperationsConfig(path string, listenAddr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "kmip" {
  path = "%s"
  listen_addrs = ["%s"]
  description = "test description"
}

resource "vault_kmip_secret_scope" "scope-1" {
    path = vault_kmip_secret_backend.kmip.path
    scope = "scope-1"
}

resource "vault_kmip_secret_role" "test" {
    path = vault_kmip_secret_scope.scope-1.path
    scope = "scope-1"
    role = "test"
	tls_client_key_type = "ec"
 	tls_client_key_bits = 256
	
	# New operation fields
	operation_import = true
	operation_query = true
	operation_encrypt = true
	operation_decrypt = true
	operation_create_key_pair = true
	operation_delete_attribute = true
	operation_rng_retrieve = true
	operation_mac = true
	operation_signature_verify = true
	operation_sign = true
	operation_rng_seed = true
	operation_modify_attribute = true
	operation_mac_verify = true
	operation_rekey_key_pair = true
}
`, path, listenAddr)
}
