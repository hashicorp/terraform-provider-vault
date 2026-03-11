// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtGCPKMS(t *testing.T) {
	gcpCredentials, gcpProject := testutil.GetTestGCPCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("gcpkms")
	resourceType := "vault_keymgmt_gcp_kms"
	resourceName := resourceType + ".test"

	gcpLocation := os.Getenv("GOOGLE_CLOUD_LOCATION")
	if gcpLocation == "" {
		gcpLocation = "us-east1"
	}

	gcpKeyRing := os.Getenv("GOOGLE_CLOUD_KEYRING")
	if gcpKeyRing == "" {
		gcpKeyRing = "test-keyring"
	}

	keyCollection := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", gcpProject, gcpLocation, gcpKeyRing)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtGCPKMSConfig(mount, kmsName, keyCollection, gcpProject, gcpLocation, gcpCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", keyCollection),
					resource.TestCheckResourceAttr(resourceName, "project", gcpProject),
					resource.TestCheckResourceAttr(resourceName, "location", gcpLocation),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtGCPKMSImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					"service_account_file",
				},
			},
		},
	})
}

func testAccKeymgmtGCPKMSImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		mount := rs.Primary.Attributes[consts.FieldMount]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/kms/%s", mount, name), nil
	}
}

func TestAccKeymgmtGCPKMS_update(t *testing.T) {
	gcpCredentials, gcpProject := testutil.GetTestGCPCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("gcpkms")
	resourceType := "vault_keymgmt_gcp_kms"
	resourceName := resourceType + ".test"

	gcpKeyRing := os.Getenv("GOOGLE_CLOUD_KEYRING")
	if gcpKeyRing == "" {
		gcpKeyRing = "test-keyring"
	}

	initialLocation := "us-east1"
	updatedLocation := "us-west1"
	initialKeyCollection := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", gcpProject, initialLocation, gcpKeyRing)
	updatedKeyCollection := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", gcpProject, updatedLocation, gcpKeyRing)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtGCPKMSConfig(mount, kmsName, initialKeyCollection, gcpProject, initialLocation, gcpCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", initialKeyCollection),
					resource.TestCheckResourceAttr(resourceName, "location", initialLocation),
				),
			},
			{
				Config: testKeymgmtGCPKMSConfig(mount, kmsName, updatedKeyCollection, gcpProject, updatedLocation, gcpCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", updatedKeyCollection),
					resource.TestCheckResourceAttr(resourceName, "location", updatedLocation),
				),
			},
		},
	})
}

func TestAccKeymgmtGCPKMS_multiple(t *testing.T) {
	gcpCredentials, gcpProject := testutil.GetTestGCPCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName1 := acctest.RandomWithPrefix("gcpkms-1")
	kmsName2 := acctest.RandomWithPrefix("gcpkms-2")
	resourceName1 := "vault_keymgmt_gcp_kms.test1"
	resourceName2 := "vault_keymgmt_gcp_kms.test2"

	gcpKeyRing := os.Getenv("GOOGLE_CLOUD_KEYRING")
	if gcpKeyRing == "" {
		gcpKeyRing = "test-keyring"
	}

	keyCollection1 := fmt.Sprintf("projects/%s/locations/us-east1/keyRings/%s", gcpProject, gcpKeyRing)
	keyCollection2 := fmt.Sprintf("projects/%s/locations/us-west1/keyRings/%s", gcpProject, gcpKeyRing)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtGCPKMSConfigMultiple(mount, kmsName1, kmsName2, keyCollection1, keyCollection2, gcpProject, gcpCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldName, kmsName1),
					resource.TestCheckResourceAttr(resourceName1, "key_collection", keyCollection1),
					resource.TestCheckResourceAttr(resourceName1, "location", "us-east1"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldName, kmsName2),
					resource.TestCheckResourceAttr(resourceName2, "key_collection", keyCollection2),
					resource.TestCheckResourceAttr(resourceName2, "location", "us-west1"),
				),
			},
		},
	})
}

func TestAccKeymgmtGCPKMS_namespace(t *testing.T) {
	gcpCredentials, gcpProject := testutil.GetTestGCPCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("gcpkms")
	namespace := acctest.RandomWithPrefix("ns")
	resourceType := "vault_keymgmt_gcp_kms"
	resourceName := resourceType + ".test"

	gcpKeyRing := os.Getenv("GOOGLE_CLOUD_KEYRING")
	if gcpKeyRing == "" {
		gcpKeyRing = "test-keyring"
	}

	keyCollection := fmt.Sprintf("projects/%s/locations/us-east1/keyRings/%s", gcpProject, gcpKeyRing)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtGCPKMSConfigNamespace(namespace, mount, kmsName, keyCollection, gcpProject, "us-east1", gcpCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", keyCollection),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespace),
				),
			},
		},
	})
}

func testKeymgmtGCPKMSConfig(mount, kmsName, keyCollection, gcpProject, gcpLocation, gcpCredentials string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_gcp_kms" "test" {
  mount                = vault_mount.keymgmt.path
  name                 = %q
  key_collection       = %q
  service_account_file = %q
  project              = %q
  location             = %q
}
`, mount, kmsName, keyCollection, gcpCredentials, gcpProject, gcpLocation)
}

func testKeymgmtGCPKMSConfigMultiple(mount, kmsName1, kmsName2, keyCollection1, keyCollection2, gcpProject, gcpCredentials string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_gcp_kms" "test1" {
  mount                = vault_mount.keymgmt.path
  name                 = %q
  key_collection       = %q
  service_account_file = %q
  project              = %q
  location             = "us-east1"
}

resource "vault_keymgmt_gcp_kms" "test2" {
  mount                = vault_mount.keymgmt.path
  name                 = %q
  key_collection       = %q
  service_account_file = %q
  project              = %q
  location             = "us-west1"
}
`, mount, kmsName1, keyCollection1, gcpCredentials, gcpProject,
		kmsName2, keyCollection2, gcpCredentials, gcpProject)
}

func testKeymgmtGCPKMSConfigNamespace(namespace, mount, kmsName, keyCollection, gcpProject, gcpLocation, gcpCredentials string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_mount" "keymgmt" {
  namespace = vault_namespace.test.path
  path      = %q
  type      = "keymgmt"
}

resource "vault_keymgmt_gcp_kms" "test" {
  namespace            = vault_namespace.test.path
  mount                = vault_mount.keymgmt.path
  name                 = %q
  key_collection       = %q
  service_account_file = %q
  project              = %q
  location             = %q
}
`, namespace, mount, kmsName, keyCollection, gcpCredentials, gcpProject, gcpLocation)
}
