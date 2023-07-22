// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendConfigCluster_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())

	clusterPath := "http://127.0.0.1:8200/v1/pki"
	clusterAiaPath := "http://127.0.0.1:8200/v1/pki"

	resourceType := "vault_pki_secret_backend_config_cluster"
	resourceName := resourceType + ".test"
	getChecks := func(p, a string) []resource.TestCheckFunc {
		checks := []resource.TestCheckFunc{
			resource.TestCheckResourceAttr(
				resourceName, "path", p),
			resource.TestCheckResourceAttr(
				resourceName, "aia_path", a),
		}
		return checks
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				// Test that reading from an unconfigured mount succeeds
				Config: testPkiSecretBackendCertConfigClusterMountConfig(rootPath),
				Check:  testPkiSecretBackendConfigClusterEmptyRead,
			},
			{
				Config: testPkiSecretBackendCertConfigClusterConfig(
					rootPath, clusterPath, clusterAiaPath),
				Check: resource.ComposeTestCheckFunc(
					getChecks(clusterPath, clusterAiaPath)...,
				),
			},
			{
				Config: testPkiSecretBackendCertConfigClusterConfig(
					rootPath, clusterPath, clusterAiaPath),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testPkiSecretBackendCertConfigClusterConfig(
					rootPath, clusterPath+"/new", clusterAiaPath+"/new"),
				Check: resource.ComposeTestCheckFunc(
					getChecks(clusterPath+"/new", clusterAiaPath+"/new")...,
				),
			},
		},
	})
}

func testPkiSecretBackendConfigClusterEmptyRead(s *terraform.State) error {
	paths, err := listPkiClusterPaths(s)
	if err != nil {
		return err
	}
	for _, path := range paths {
		d := &schema.ResourceData{}
		d.SetId(path)
		if err := pkiSecretBackendConfigClusterRead(d, testProvider.Meta()); err != nil {
			return err
		}
	}
	return nil
}

func listPkiClusterPaths(s *terraform.State) ([]string, error) {
	var paths []string

	client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_mount" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "pki" && path == rsPath {
				paths = append(paths, path)
			}
		}
	}

	return paths, nil
}

func testPkiSecretBackendCertConfigClusterMountConfig(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = 8640000
  max_lease_ttl_seconds     = 8640000
}
`, rootPath)
}

func testPkiSecretBackendCertConfigClusterConfig(rootPath string, clusterPath string, clusterAiaPath string) string {
	return fmt.Sprintf(`
%s

resource "vault_pki_secret_backend_config_cluster" "test" {
  backend  = vault_mount.test-root.path
  path     = "%s"
  aia_path = "%s"
}
`,
		testPkiSecretBackendCertConfigClusterMountConfig(rootPath),
		clusterPath, clusterAiaPath)
}
