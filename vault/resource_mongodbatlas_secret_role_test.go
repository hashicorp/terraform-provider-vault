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
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccMongoDBAtlasSecretRole_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-mongodbatlas")
	resourceType := "vault_mongodbatlas_secret_role"
	resourceName := resourceType + ".role"

	name := "tf-test-role"
	organizationID := "7cf5a45a9ccf6400e60981b7"
	projectID := "5cf5a45a9ccf6400e60981b6"
	roles := "ORG_MEMBER"
	cidrBlocks := "192.168.1.3/32"
	projectRoles := "GROUP_CLUSTER_MANAGER"
	ttl := "30"
	maxTtl := "60"

	updatedOrganizationID := "7cf5a45a9ccf6400e60981a8"
	updatedProjectID := "5cf5a45a9ccf6400e60981a67"
	updatedRoles := "ORG_READ_ONLY"
	updatedCidrBlocks := "192.168.1.3/35"
	updatedProjectRoles := "GROUP_READ_ONLY"
	updatedTtl := "60"
	updatedMaxTtl := "120"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeMongoDBAtlas, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testAccMongoDBAtlasSecretBackendRole_initial(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
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
				Config: testAccMongoDBAtlasSecretBackendRole_updatedExceptRoles(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganizationID, updatedOrganizationID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, updatedProjectID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".0", roles),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".0", "192.168.1.5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".1", "192.168.1.6"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".0", updatedCidrBlocks),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".0", updatedProjectRoles),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, updatedTtl),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, updatedMaxTtl),
				),
			},
			{
				Config: testAccMongoDBAtlasSecretBackendRole_updatedRoles(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldOrganizationID, updatedOrganizationID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, updatedProjectID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoles+".0", updatedRoles),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".0", "192.168.1.5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIPAddresses+".1", "192.168.1.6"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCIDRBlocks+".0", updatedCidrBlocks),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectRoles+".#", "1"),
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

func testAccMongoDBAtlasSecretBackendRole_initial(path, name string) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_role" "role" {
	mount           = vault_mount.mongo.path
	name            = "%s"
	organization_id = "7cf5a45a9ccf6400e60981b7"
	project_id      = "5cf5a45a9ccf6400e60981b6"
	roles           = ["ORG_MEMBER"]
	ip_addresses    = ["192.168.1.3", "192.168.1.4"]
	cidr_blocks     = ["192.168.1.3/32"]
	project_roles   = ["GROUP_CLUSTER_MANAGER"]
	ttl             = 30
	max_ttl         = 60
}`, path, name)

	return ret
}

func testAccMongoDBAtlasSecretBackendRole_updatedExceptRoles(path, name string) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_role" "role" {
	mount           = vault_mount.mongo.path
	name            = "%s"
	organization_id = "7cf5a45a9ccf6400e60981a8"
	project_id      = "5cf5a45a9ccf6400e60981a67"
	roles           = ["ORG_MEMBER"]
	ip_addresses    = ["192.168.1.5", "192.168.1.6"]
	cidr_blocks     = ["192.168.1.3/35"]
	project_roles   = ["GROUP_READ_ONLY"]
	ttl             = 60
	max_ttl         = 120
  }`, path, name)

	return ret
}

func testAccMongoDBAtlasSecretBackendRole_updatedRoles(path, name string) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "mongo" {
	path        = "%s"
	type        = "mongodbatlas"
    description = "MongoDB Atlas secret engine mount"
}

resource "vault_mongodbatlas_secret_role" "role" {
	mount           = vault_mount.mongo.path
	name            = "%s"
	organization_id = "7cf5a45a9ccf6400e60981a8"
	project_id      = "5cf5a45a9ccf6400e60981a67"
	roles           = ["ORG_READ_ONLY"]
	ip_addresses    = ["192.168.1.5", "192.168.1.6"]
	cidr_blocks     = ["192.168.1.3/35"]
	project_roles   = ["GROUP_READ_ONLY"]
	ttl             = 60
	max_ttl         = 120
  }`, path, name)

	return ret
}
