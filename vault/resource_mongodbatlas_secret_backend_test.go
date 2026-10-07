// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccMongoDBAtlasSecretBackend_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-mongodbatlas")
	resourceType := "vault_mongodbatlas_secret_backend"
	resourceName := resourceType + ".test"
	privateKey, publicKey := testutil.GetTestMDBACreds(t)

	updatedPrivateKey := "905ae89e-6ee8-40rd-ab12-613t8e3fe836"
	updatedPublicKey := "klpruxce"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_basic(mount, privateKey, publicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/config", mount)),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKey, privateKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKey, publicKey),
				),
			},
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_basic(mount, updatedPrivateKey, updatedPublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/config", mount)),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKey, updatedPrivateKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKey, updatedPublicKey),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldPrivateKey,
					consts.FieldPrivateKeyWO,
					consts.FieldPrivateKeyWOVersion,
				},
			},
		},
	})
}

func TestAccMongoDBAtlasSecretBackend_WriteOnly(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-mongodbatlas-wo")
	resourceType := "vault_mongodbatlas_secret_backend"
	resourceName := resourceType + ".test"
	privateKey, publicKey := testutil.GetTestMDBACreds(t)

	updatedPrivateKey := "905ae89e-6ee8-40rd-ab12-613t8e3fe836"
	updatedPublicKey := "klpruxce"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_writeOnly(mount, privateKey, publicKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/config", mount)),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKeyWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKey, publicKey),
					// private_key should not be in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldPrivateKey),
				),
			},
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_writeOnly(mount, updatedPrivateKey, updatedPublicKey, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/config", mount)),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKeyWOVersion, "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKey, updatedPublicKey),
					// private_key should not be in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldPrivateKey),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldPrivateKey,
					consts.FieldPrivateKeyWO,
					consts.FieldPrivateKeyWOVersion,
				},
			},
		},
	})
}

func TestAccMongoDBAtlasSecretBackend_LegacyFields(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-mongodbatlas-legacy")
	resourceType := "vault_mongodbatlas_secret_backend"
	resourceName := resourceType + ".test"
	privateKey, publicKey := testutil.GetTestMDBACreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_basic(mount, privateKey, publicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKey, privateKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKey, publicKey),
				),
			},
		},
	})
}

func TestAccMongoDBAtlasSecretBackend_writeOnlyConflicts(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-mongodbatlas-conflicts")
	privateKey, publicKey := testutil.GetTestMDBACreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Negative Test 1: private_key and private_key_wo cannot be used together
			{
				Config:      testAccMongoDBAtlasSecretBackendConfig_privateKeyConflict(mount, privateKey, publicKey, 1),
				ExpectError: regexp.MustCompile(`only one of .+private_key,private_key_wo.+ can be specified`),
			},
			// Negative Test 2: private_key_wo_version requires private_key_wo
			{
				Config:      testAccMongoDBAtlasSecretBackendConfig_versionWithoutPrivateKeyWO(mount, privateKey, publicKey),
				ExpectError: regexp.MustCompile(`all of .+private_key_wo.+private_key_wo_version.+ must\s+be specified`),
			},
			// Negative Test 3: neither private_key nor private_key_wo provided
			{
				Config:      testAccMongoDBAtlasSecretBackendConfig_noPrivateKey(mount, publicKey),
				ExpectError: regexp.MustCompile(`one of .+private_key,private_key_wo.+ must be specified`),
			},
		},
	})
}

func testAccMongoDBAtlasSecretBackendConfig_basic(path, privateKey, publicKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_backend" "test" {
  mount 	   = vault_mount.mongo.path
  private_key  = "%s"
  public_key   = "%s"
}`, path, privateKey, publicKey)
}

func testAccMongoDBAtlasSecretBackendConfig_writeOnly(path, privateKey, publicKey string, version int) string {
	return fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_backend" "test" {
  mount                   = vault_mount.mongo.path
  private_key_wo          = "%s"
  private_key_wo_version  = %d
  public_key              = "%s"
}`, path, privateKey, version, publicKey)
}

// Negative test configs
func testAccMongoDBAtlasSecretBackendConfig_privateKeyConflict(path, privateKey, publicKey string, version int) string {
	return fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_backend" "test" {
  mount                   = vault_mount.mongo.path
  private_key             = "%s"
  private_key_wo          = "%s"
  private_key_wo_version  = %d
  public_key              = "%s"
}`, path, privateKey, privateKey, version, publicKey)
}

func testAccMongoDBAtlasSecretBackendConfig_versionWithoutPrivateKeyWO(path, privateKey, publicKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_backend" "test" {
  mount                   = vault_mount.mongo.path
  private_key             = "%s"
  private_key_wo_version  = 1
  public_key              = "%s"
}`, path, privateKey, publicKey)
}

func testAccMongoDBAtlasSecretBackendConfig_noPrivateKey(path, publicKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_backend" "test" {
  mount       = vault_mount.mongo.path
  public_key  = "%s"
}`, path, publicKey)
}

// testAccMongoDBAtlasSecretBackendConfig_writeOnlyWithPublicKey is identical
// to testAccMongoDBAtlasSecretBackendConfig_writeOnly but takes the public
// key as a parameter so the regression test can vary it across applies.
func testAccMongoDBAtlasSecretBackendConfig_writeOnlyWithPublicKey(path, privateKey string, version int, publicKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_backend" "test" {
  mount                   = vault_mount.mongo.path
  private_key_wo          = "%s"
  private_key_wo_version  = %d
  public_key              = "%s"
}`, path, privateKey, version, publicKey)
}

// TestAccMongoDBAtlasSecretBackend_writeOnlyPersistsOnUnrelatedUpdate is a
// regression test for the bug where updating an unrelated field while
// private_key_wo_version stays unchanged caused the provider to omit
// `private_key` from the request to the full-replace `<mount>/config`
// endpoint. The mongodbatlas plugin rejects an empty private_key with
// `private_key is empty`, so the bug surfaces as a hard apply failure
// rather than silent data loss.
//
// See https://github.com/hashicorp/terraform-provider-vault/issues/2900.
func TestAccMongoDBAtlasSecretBackend_writeOnlyPersistsOnUnrelatedUpdate(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-mongodbatlas-wo-unrelated")
	resourceType := "vault_mongodbatlas_secret_backend"
	resourceName := resourceType + ".test"
	privateKey, publicKey := testutil.GetTestMDBACreds(t)
	updatedPublicKey := publicKey + "-v2"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_writeOnlyWithPublicKey(
					mount, privateKey, 1, publicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKeyWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKey, publicKey),
				),
			},
			{
				// Update only `public_key`; keep private_key_wo_version at 1.
				// Before the fix, this apply would fail because the provider
				// would resolve private_key to "" and the mongodbatlas plugin
				// would reject the empty private_key.
				Config: testAccMongoDBAtlasSecretBackendConfig_writeOnlyWithPublicKey(
					mount, privateKey, 1, updatedPublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPublicKey, updatedPublicKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKeyWOVersion, "1"),
				),
			},
		},
	})
}
