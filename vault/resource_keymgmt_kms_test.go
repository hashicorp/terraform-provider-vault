// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtKms_aws(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	// Skip if AWS credentials are not available
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Skip("AWS_ACCESS_KEY_ID not set, skipping AWS KMS test")
	}

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	resourceType := "vault_keymgmt_kms"
	resourceName := resourceType + ".test"

	awsRegion := "us-west-2"
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		awsRegion = region
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKms_awsConfig(mount, kmsName, awsRegion),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "kms_provider", "awskms"),
					resource.TestCheckResourceAttr(resourceName, "key_collection", awsRegion),
					resource.TestCheckResourceAttr(resourceName, "region", awsRegion),
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// credentials are not returned by the API
				ImportStateVerifyIgnore: []string{"credentials"},
			},
		},
	})
}

func testKeymgmtKms_awsConfig(mount, kmsName, region string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_kms" "test" {
  path           = vault_mount.keymgmt.path
  name           = %q
  kms_provider   = "awskms"
  key_collection = %q
  region         = %q
  
  credentials = {
    access_key = "%s"
    secret_key = "%s"
  }
}
`, mount, kmsName, region, region, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
}
