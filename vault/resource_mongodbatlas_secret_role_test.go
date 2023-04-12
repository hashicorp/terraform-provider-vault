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
	name := "tf-test-role"
	organizationID := "7cf5a45a9ccf6400e60981b7"
	projectID := "5cf5a45a9ccf6400e60981b6"
	roles := "ORG_MEMBER"
	ipAddresses := "192.168.1.3, 192.168.1.4"
	cidrBlocks := "192.168.1.3/32"
	projectRoles := "GROUP_CLUSTER_MANAGER"
	ttl := "30"
	maxTtl := "60"

	updatedName := "tf-test-role-updated"
	updatedOrganizationID := "7cf5a45a9ccf6400e60981a8"
	updatedProjectID := "5cf5a45a9ccf6400e60981a67"
	updatedRoles := "ORG_READ_ONLY"
	updatedIpAddresses := "192.168.1.5, 192.168.1.6"
	updatedCidrBlocks := "192.168.1.3/35"
	updatedProjectRoles := "GROUP_READ_ONLY"
	updatedTtl := "60"
	updatedMaxTtl := "120"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendRole_basic(mount, privateKey, publicKey, name, organizationID,
					projectID, roles, ipAddresses, cidrBlocks, projectRoles, ttl, maxTtl),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganizationID, organizationID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, projectID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".0", roles),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".0", "192.168.1.3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".1", "192.168.1.4"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".0", cidrBlocks),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".0", projectRoles),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, ttl),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, maxTtl),
				),
			},
			{
				Config: testAccMongoDBAtlasSecretBackendRole_basic(mount, privateKey, publicKey, updatedName,
					updatedOrganizationID, updatedProjectID, updatedRoles, updatedIpAddresses, updatedCidrBlocks,
					updatedProjectRoles, updatedTtl, updatedMaxTtl),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganizationID, updatedOrganizationID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, updatedProjectID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+"#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".0", updatedRoles),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+"#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".0", "192.168.1.5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".1", "192.168.1.6"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+"#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".0", updatedCidrBlocks),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+"#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".0", updatedProjectRoles),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, updatedTtl),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, updatedMaxTtl),
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
