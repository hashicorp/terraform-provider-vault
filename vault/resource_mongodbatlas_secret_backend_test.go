// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccMongoDBAtlasSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-mongodbatlas")
	resourceType := "vault_mongodbatlas_secret_backend"
	resourceName := resourceType + ".test"
	publicKey, privateKey := testutil.GetTestMDBACreds(t)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_basic(path, privateKey, publicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "private_key", "2c130c23-e6b6-4da8-a93f-a8bf33218830"),
					resource.TestCheckResourceAttr(resourceName, "public_key", "yhltsvan"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_updated(path, privateKey, publicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "private_key", "905ae89e-6ee8-40rd-ab12-613t8e3fe836"),
					resource.TestCheckResourceAttr(resourceName, "public_key", "klpruxce"),
				),
			},
		},
	})
}

func TestAccMongoDBAtlasSecretBackend_template(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-mongodbatlas")
	resourceType := "vault_mongodbatlas_secret_backend"
	resourceName := resourceType + ".test"
	privateKey, publicKey := testutil.GetTestMDBACreds(t)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendTemplateConfig(path, privateKey, publicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "private_key", privateKey),
					resource.TestCheckResourceAttr(resourceName, "public_key", publicKey),
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

func TestMongoDBAtlasSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-mongodbatlas")
	updatedPath := acctest.RandomWithPrefix("tf-test-mongodbatlas-updated")

	resourceName := "vault_mongodbatlas_secret_backend.test"
	privateKey, publicKey := testutil.GetTestMDBACreds(t)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_basic(path, privateKey, publicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "private_key", privateKey),
					resource.TestCheckResourceAttr(resourceName, "public_key", publicKey),
				),
			},
			{
				Config: testAccMongoDBAtlasSecretBackendConfig_updated(updatedPath, privateKey, publicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, "private_key", privateKey),
					resource.TestCheckResourceAttr(resourceName, "public_key", publicKey),
				),
			},
		},
	})
}

func testAccMongoDBAtlasSecretBackendConfig_basic(path, privateKey, publicKey string) string {
	return fmt.Sprintf(`
resource "vault_mongodbatlas_secret_backend" "test" {
  path = "%s"
  private_key = "%s"
  public_key = "%s"
}`, path, privateKey, publicKey)
}

func testAccMongoDBAtlasSecretBackendConfig_updated(path, privateKey, publicKey string) string {
	return fmt.Sprintf(`
resource "vault_mongodbatlas_secret_backend" "test" {
  path = "%s"
  private_key = "%s"
  public_key = "%s"
}`, path, privateKey, publicKey)
}

func testAccMongoDBAtlasSecretBackendTemplateConfig(path, privateKey, publicKey string) string {
	return fmt.Sprintf(`
resource "vault_mongodbatlas_secret_backend" "test" {
  path           = "%s"
  private_key    = "%s"
  public_key     = "%s"
}`, path, privateKey, publicKey)
}
