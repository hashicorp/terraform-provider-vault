// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtDistributeKey(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_keymgmt_distribute_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtDistributeKeyConfig(backend, kmsName, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_name", keyName),
					resource.TestCheckResourceAttr(resourceName, "purpose.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "protection", "hsm"),
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

resource "vault_keymgmt_kms" "test" {
  path           = vault_mount.test.path
  name           = "%s"
  kms_provider   = "awskms"
  key_collection = "us-west-1"
  region         = "us-west-1"
  
  credentials = {
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}

resource "vault_keymgmt_distribute_key" "test" {
  path       = vault_mount.test.path
  kms_name   = vault_keymgmt_kms.test.name
  key_name   = vault_keymgmt_key.test.name
  purpose    = ["encrypt", "decrypt"]
  protection = "hsm"
}
`, path, keyName, kmsName)
}
