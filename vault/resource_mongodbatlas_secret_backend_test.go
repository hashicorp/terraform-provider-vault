// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldPrivateKey},
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
