// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccMongoDBAtlasSecretRole_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-mongodbatlas")
	resourceType := "vault_mongodbatlas_secret_role"
	resourceName := resourceType + ".role"
	privateKey, publicKey := testutil.GetTestMDBACreds(t)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendRole_basic(mount, privateKey, publicKey, "tf-test-role",
					"7cf5a45a9ccf6400e60981b7", "5cf5a45a9ccf6400e60981b6", "ORG_MEMBER",
					"192.168.1.3, 192.168.1.4", "192.168.1.3/32",
					"GROUP_CLUSTER_MANAGER", "30min", "1hr"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "tf-test-role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganizationID,
						"7cf5a45a9ccf6400e60981b7"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, "5cf5a45a9ccf6400e60981b6"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".0", "ORG_MEMBER"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".0", "192.168.1.3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".1", "192.168.1.4"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".0", "192.168.1.3/32"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".0",
						"GROUP_CLUSTER_MANAGER"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "60"),
				),
			},
			{
				Config: testAccMongoDBAtlasSecretBackendRole_basic(mount, privateKey, publicKey,
					"tf-test-role-updated", "7cf5a45a9ccf6400e60981b7",
					"5cf5a45a9ccf6400e60981b6", "ORG_READ_ONLY", "192.168.1.5, 192.168.1.6",
					"192.168.1.3/35", "GROUP_READ_ONLY", "30min", "1hr"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "tf-test-role-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganizationID,
						"7cf5a45a9ccf6400e60981b7"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, "5cf5a45a9ccf6400e60981b6"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+"#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".0", "ORG_READ_ONLY"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+"#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".0", "192.168.1.5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".1", "192.168.1.6"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+"#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".0", "192.168.1.3/35"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+"#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".0", "GROUP_READ_ONLY"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "120"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccMongoDBAtlasSecretBackendRole_basic(path, privateKey, publicKey, name, organizationID, projectID, roles,
	ipAddresses, cidrBlocks, projectRoles, ttl, maxTtl string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
	private_key = "%s"
  	public_key 	= "%s"
}
resource "vault_mongodbatlas_secret_role" "role" {
  backend = vault_mount.mongo.path
  name              = "%s"
  organization_id   = "%s"
  project_id        = "%s"
  roles             = [%q]
  ip_addresses      = [%q]
  cidr_blocks       = [%q]
  project_roles     = [%q]
  ttl               = "%s"
  max_ttl           = "%s"
}`, path, privateKey, publicKey, name, organizationID, projectID, roles, ipAddresses, cidrBlocks, projectRoles, ttl, maxTtl)
}
