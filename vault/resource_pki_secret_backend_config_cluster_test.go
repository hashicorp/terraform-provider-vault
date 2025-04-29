// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendConfigCluster_basic(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("pki-root")
	resourceType := "vault_pki_secret_backend_config_cluster"
	resourceName := resourceType + ".test"

	clusterPath := "http://127.0.0.1:8200/v1/pki"
	clusterAiaPath := "http://127.0.0.1:8200/v1/pki"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendConfigCluster(backend, "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAIAPath, ""),
				),
			},
			{
				Config: testPkiSecretBackendConfigCluster(backend, clusterPath, clusterAiaPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, clusterPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAIAPath, clusterAiaPath),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testPkiSecretBackendConfigCluster(path, clusterPath string, clusterAiaPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path                      = "%s"
	type                      = "pki"
	description               = "PKI secret engine mount"
  default_lease_ttl_seconds = 8640000
  max_lease_ttl_seconds     = 8640000
}

resource "vault_pki_secret_backend_config_cluster" "test" {
  backend  = vault_mount.test.path
  path     = "%s"
  aia_path = "%s"
}`, path, clusterPath, clusterAiaPath)
}
