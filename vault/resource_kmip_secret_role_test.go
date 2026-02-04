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
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRevoke, "false"),
				),
			},
			{
				Config: testKMIPSecretRole_updatedConfig(path, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSClientKeyType, "rsa"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSClientKeyBits, "4096"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGetAttributeList, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationCreate, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDestroy, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRevoke, "false"),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRevoke, "false"),
				),
			},
			{
				Config: testKMIPSecretRole_initialConfig(remountPath, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, remountPath),
					resource.TestCheckResourceAttr(resourceName, "scope", "scope-1"),
					resource.TestCheckResourceAttr(resourceName, "role", "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSClientKeyType, "ec"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTLSClientKeyBits, "256"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationActivate, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGet, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGetAttributes, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAddAttribute, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationCreate, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDestroy, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDiscoverVersions, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGetAttributeList, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationLocate, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationNone, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRegister, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRekey, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRevoke, "false"),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationImport, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationQuery, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationEncrypt, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDecrypt, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationCreateKeyPair, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationDeleteAttribute, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRNGRetrieve, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationMAC, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationSignatureVerify, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationSign, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRNGSeed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationModifyAttribute, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationMACVerify, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationRekeyKeyPair, "true"),
					// Existing operations should be false
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationActivate, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationGet, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationAll, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOperationNone, "false"),
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
