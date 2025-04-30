// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestSecretsSyncAssociation_gh(t *testing.T) {
	var p *schema.Provider
	mount := acctest.RandomWithPrefix("tf-test-sync")
	destName := acctest.RandomWithPrefix("tf-sync-dest")
	secretName := acctest.RandomWithPrefix("tf-sync-secret")

	resourceName := "vault_secrets_sync_association.test"

	values := testutil.SkipTestEnvUnset(t,
		"GITHUB_ACCESS_TOKEN",
		"GITHUB_REPO_OWNER",
		"GITHUB_REPO_NAME",
	)

	accessToken := values[0]
	repoOwner := values[1]
	repoName := values[2]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testSecretsSyncAssociationConfig_gh(mount, accessToken, repoOwner, repoName, destName, secretName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldSecretName, secretName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, ghSyncType),
					resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("%s.#", consts.FieldMetadata), "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.0.sub_key", ""),
					resource.TestCheckResourceAttrSet(resourceName, "metadata.0.sync_status"),
					resource.TestCheckResourceAttrSet(resourceName, "metadata.0.updated_at"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testSecretsSyncAssociationConfig_gh(mount, accessToken, owner, repoName, destName, secretName string) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "test" {
 path        = "%s"
 type        = "kv"
 options     = { version = "2" }
}

resource "vault_kv_secret_v2" "test" {
 mount = vault_mount.test.path
 name  = "%s"
 data_json = jsonencode(
   {
     dev  = "B!gS3cr3t",
     prod = "S3cureP4$$"
   }
 )
}

resource "vault_secrets_sync_gh_destination" "test" {
  name                 = "%s"
  access_token         = "%s"
  repository_owner     = "%s"
  repository_name      = "%s"
  granularity          = "secret-path"
}

resource "vault_secrets_sync_association" "test" {
  name        = vault_secrets_sync_gh_destination.test.name
  type        = vault_secrets_sync_gh_destination.test.type
  mount       = vault_mount.test.path
  secret_name = vault_kv_secret_v2.test.name
}`, mount, secretName, destName, accessToken, owner, repoName)

	return ret
}
