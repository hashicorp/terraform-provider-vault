// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtGCPKMS(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "GOOGLE_CREDENTIALS")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("gcpkms")
	resourceType := "vault_keymgmt_gcp_kms"
	resourceName := resourceType + ".test"

	gcpProject := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if gcpProject == "" {
		gcpProject = "test-project"
	}

	gcpLocation := os.Getenv("GOOGLE_CLOUD_LOCATION")
	if gcpLocation == "" {
		gcpLocation = "us-east1"
	}

	gcpKeyRing := os.Getenv("GOOGLE_CLOUD_KEYRING")
	if gcpKeyRing == "" {
		gcpKeyRing = "test-keyring"
	}

	keyCollection := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", gcpProject, gcpLocation, gcpKeyRing)
	gcpCredentials := os.Getenv("GOOGLE_CREDENTIALS")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtGCPKMSConfig(mount, kmsName, keyCollection, gcpProject, gcpLocation, gcpCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", keyCollection),
					resource.TestCheckResourceAttr(resourceName, "project", gcpProject),
					resource.TestCheckResourceAttr(resourceName, "location", gcpLocation),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"service_account_file",
			),
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
  path                 = vault_mount.keymgmt.path
  name                 = %q
  key_collection       = %q
  service_account_file = %q
  project              = %q
  location             = %q
}
`, mount, kmsName, keyCollection, gcpCredentials, gcpProject, gcpLocation)
}
