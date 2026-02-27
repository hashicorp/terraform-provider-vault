// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPSecretScope_remount(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	remountPath := acctest.RandomWithPrefix("tf-test-kmip-updated")
	resourceType := "vault_kmip_secret_scope"
	resourceName := resourceType + ".test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	addr1 := lns[0].Addr().String()
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeKMIP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretScope_initialConfig(path, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "scope", "test"),
				),
			},
			{
				Config: testKMIPSecretScope_initialConfig(remountPath, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, remountPath),
					resource.TestCheckResourceAttr(resourceName, "scope", "test"),
				),
			},
		},
	})
}

func testKMIPSecretScope_initialConfig(path string, listenAddr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "kmip" {
  path = "%s"
  listen_addrs = ["%s"]
  description = "test description"
}

resource "vault_kmip_secret_scope" "test" {
    path = vault_kmip_secret_backend.kmip.path
    scope = "test"
}`, path, listenAddr)
}
