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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtDistributeKey(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")

	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_keymgmt_distribute_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtDistributeKeyConfig(backend, kmsName, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_name", keyName),
					resource.TestCheckResourceAttr(resourceName, "purpose.#", "2"), resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "encrypt"),
					resource.TestCheckTypeSetElemAttr(resourceName, "purpose.*", "decrypt"), resource.TestCheckResourceAttr(resourceName, "protection", "hsm"),
					resource.TestCheckResourceAttrSet(resourceName, "key_id"),
				),
			},
		},
	})
}

func testKeymgmtDistributeKeyConfig(path, kmsName, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
}

resource "vault_keymgmt_aws_kms" "test" {
  path           = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"
  
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_keymgmt_distribute_key" "test" {
  path       = vault_mount.test.path
  kms_name   = vault_keymgmt_aws_kms.test.name
  key_name   = vault_keymgmt_key.test.name
  purpose    = ["encrypt", "decrypt"]
  protection = "hsm"
}
`, path, keyName, kmsName, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
}
