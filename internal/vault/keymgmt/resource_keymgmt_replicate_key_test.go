// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccKeymgmtReplicateKey(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_keymgmt_replicate_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtReplicateKeyConfig(backend, kmsName, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "kms_name", kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_name", keyName),
				),
			},
		},
	})
}

func TestAccKeymgmtReplicateKey_NoReplicaRegions(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("awskms")
	keyName := acctest.RandomWithPrefix("test-key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtReplicateKeyConfig_NoReplicaRegions(backend, kmsName, keyName),
				ExpectError: regexp.MustCompile("replica_regions must be configured"),
			},
		},
	})
}

func testKeymgmtReplicateKeyConfig(path, kmsName, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path            = vault_mount.test.path
  name            = "%s"
  type            = "aes256-gcm96"
  replica_regions = ["us-east-1", "eu-west-1"]
}

resource "vault_keymgmt_aws_kms" "test" {
  path           = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"
  region         = "us-west-1"
  
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "vault_keymgmt_distribute_key" "test" {
  path       = vault_mount.test.path
  kms_name   = vault_keymgmt_aws_kms.test.name
  key_name   = vault_keymgmt_key.test.name
  purpose    = ["encrypt", "decrypt"]
  protection = "hsm"
}

resource "vault_keymgmt_replicate_key" "test" {
  path     = vault_mount.test.path
  kms_name = vault_keymgmt_aws_kms.test.name
  key_name = vault_keymgmt_key.test.name
  
  depends_on = [vault_keymgmt_distribute_key.test]
}
`, path, keyName, kmsName)
}

func testKeymgmtReplicateKeyConfig_NoReplicaRegions(path, kmsName, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path = vault_mount.test.path
  name = "%s"
  type = "aes256-gcm96"
  # No replica_regions specified
}

resource "vault_keymgmt_aws_kms" "test" {
  path           = vault_mount.test.path
  name           = "%s"
  key_collection = "us-west-1"
  region         = "us-west-1"
  
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "vault_keymgmt_distribute_key" "test" {
  path       = vault_mount.test.path
  kms_name   = vault_keymgmt_aws_kms.test.name
  key_name   = vault_keymgmt_key.test.name
  purpose    = ["encrypt", "decrypt"]
  protection = "hsm"
}

resource "vault_keymgmt_replicate_key" "test" {
  path     = vault_mount.test.path
  kms_name = vault_keymgmt_aws_kms.test.name
  key_name = vault_keymgmt_key.test.name
  
  depends_on = [vault_keymgmt_distribute_key.test]
}
`, path, keyName, kmsName)
}
