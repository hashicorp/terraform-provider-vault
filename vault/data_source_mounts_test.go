// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceMounts(t *testing.T) {
	kvPath := acctest.RandomWithPrefix("tf-test-kv-backend")
	pkiPath := acctest.RandomWithPrefix("tf-test-pki-backend")
	dataName := "data.vault_mounts.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testMountsDataSource(kvPath, pkiPath),
				Check: resource.ComposeTestCheckFunc(
					testCheckMountInList(dataName, kvPath+"/", "kv"),
					testCheckMountInList(dataName, pkiPath+"/", "pki"),
				),
			},
		},
	})
}

func testMountsDataSource(kvPath, pkiPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kv" {
	path        = "%s"
	type        = "kv"
    description = "KV secret engine mount"
}

resource "vault_mount" "pki" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}


data "vault_mounts" "test" {
    depends_on = [ vault_mount.kv,vault_mount.pki ]
}`, kvPath, pkiPath)
}

func testCheckMountInList(name, expectedPath, expectedType string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("resource %s not found", name)
		}

		countStr := rs.Primary.Attributes["mounts.#"]
		count, err := strconv.Atoi(countStr)
		if err != nil {
			return err
		}

		for i := range count {
			path := rs.Primary.Attributes[fmt.Sprintf("mounts.%d.path", i)]
			typ := rs.Primary.Attributes[fmt.Sprintf("mounts.%d.type", i)]
			if path == expectedPath && typ == expectedType {
				return nil
			}
		}
		return fmt.Errorf("mount with path %s and type %s not found", expectedPath, expectedType)
	}
}
