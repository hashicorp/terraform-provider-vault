// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider/fwprovider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// testAccProtoV5ProviderFactories returns a map of provider factories for acceptance tests
func testAccProtoV5ProviderFactories(ctx context.Context, t *testing.T) map[string]func() (tfprotov5.ProviderServer, error) {
	return map[string]func() (tfprotov5.ProviderServer, error){
		"vault": func() (tfprotov5.ProviderServer, error) {
			return providerserver.NewProtocol5(fwprovider.New())(), nil
		},
	}
}

// GetTestAliCloudCreds retrieves AliCloud credentials from environment variables
func GetTestAliCloudCreds(t *testing.T) (string, string) {
	t.Helper()
	v := testutil.SkipTestEnvUnset(t, "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY")
	return v[0], v[1]
}

// TestAccAliCloudSecretBackend_basic tests basic CRUD operations
func TestAccAliCloudSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := GetTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckAliCloudSecretBackendDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					// secret_key_wo is write-only, so it should not be in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
			},
			// Test import
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldSecretKeyWO, consts.FieldSecretKeyWOVersion},
			},
		},
	})
}

// TestAccAliCloudSecretBackend_update tests updating the backend configuration
func TestAccAliCloudSecretBackend_update(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := GetTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckAliCloudSecretBackendDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
			},
			// Update access_key only (version stays same)
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey+"-updated", secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey+"-updated"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
			},
			// Update secret_key_wo by incrementing version
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey+"-updated", secretKey+"-updated", 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey+"-updated"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
				),
			},
			// Update both access_key and secret_key_wo
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey, secretKey, 3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "3"),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackend_versionDecrement tests that version can be decremented
func TestAccAliCloudSecretBackend_versionDecrement(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := GetTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckAliCloudSecretBackendDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey, secretKey, 10),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "10"),
				),
			},
			// Decrement version (should trigger update)
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey, secretKey+"-updated", 5),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "5"),
				),
			},
			// Decrement to 1
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackend_remount tests remounting the backend to a new path
func TestAccAliCloudSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	updatedPath := acctest.RandomWithPrefix("tf-test-alicloud-updated")
	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := GetTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckAliCloudSecretBackendDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendConfig_basic(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
				),
			},
			// Change path (should trigger remount)
			{
				Config: testAccAliCloudSecretBackendConfig_basic(updatedPath, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackend_noCreds tests backend without credentials (using Vault's default auth)
func TestAccAliCloudSecretBackend_noCreds(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-alicloud")
	resourceType := "vault_alicloud_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckAliCloudSecretBackendDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendConfig_noCreds(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, ""),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWOVersion),
				),
			},
		},
	})
}

// testCheckAliCloudSecretBackendDestroyed verifies the backend was destroyed
func testCheckAliCloudSecretBackendDestroyed(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_alicloud_secret_backend" {
			continue
		}

		client := testutil.GetTestClient(nil)
		mounts, err := client.Sys().ListMounts()
		if err != nil {
			return err
		}

		path := rs.Primary.ID
		if _, ok := mounts[path+"/"]; ok {
			return fmt.Errorf("AliCloud secret backend still exists at path: %s", path)
		}
	}
	return nil
}

// testAccAliCloudSecretBackendConfig_basic returns a basic test configuration
func testAccAliCloudSecretBackendConfig_basic(path, accessKey, secretKey string, version int) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                   = %q
  access_key             = %q
  secret_key_wo          = %q
  secret_key_wo_version  = %d
}
`, path, accessKey, secretKey, version)
}

// testAccAliCloudSecretBackendConfig_noCreds returns a configuration without credentials
func testAccAliCloudSecretBackendConfig_noCreds(path string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path = %q
}
`, path)
}

// Made with Bob
