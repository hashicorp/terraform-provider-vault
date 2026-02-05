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

func TestAccKeymgmtKms_aws(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	// Skip if AWS credentials are not available
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Skip("AWS_ACCESS_KEY_ID not set, skipping AWS KMS test")
	}

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	resourceType := "vault_keymgmt_aws_kms"
	resourceName := resourceType + ".test"

	awsRegion := "us-west-2"
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		awsRegion = region
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKms_awsConfig(mount, kmsName, awsRegion),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
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
				ImportStateVerifyIgnore: []string{"access_key", "secret_key"},
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

resource "vault_keymgmt_aws_kms" "test" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  region         = %q
  
  access_key = "%s"
  secret_key = "%s"
}
`, mount, kmsName, region, region, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
}
