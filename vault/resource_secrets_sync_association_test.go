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

func TestSecretsSyncAssociation_gh(t *testing.T) {
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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

// TestSyncAssociationFieldsFromID tests the ID parsing logic for vault_secrets_sync_association
// This is a unit test for the syncAssociationFieldsFromID function that parses resource IDs.
func TestSyncAssociationFieldsFromID(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantType   string
		wantDest   string
		wantMount  string
		wantSecret string
		wantErr    bool
	}{
		{
			name:       "simple secret name without slashes",
			id:         "gcp-sm/dest/gcp-secret-manager/mount/kvv2-gcp3/secret/token",
			wantType:   "gcp-sm",
			wantDest:   "gcp-secret-manager",
			wantMount:  "kvv2-gcp3",
			wantSecret: "token",
			wantErr:    false,
		},
		{
			name:       "secret name with single slash",
			id:         "gcp-sm/dest/gcp-secret-manager/mount/kvv2-gcp3/secret/api/key",
			wantType:   "gcp-sm",
			wantDest:   "gcp-secret-manager",
			wantMount:  "kvv2-gcp3",
			wantSecret: "api/key",
			wantErr:    false,
		},
		{
			name:       "secret name with deep nesting",
			id:         "aws-sm/dest/aws-dest-1/mount/kv-v2/secret/prod/app/database/credentials",
			wantType:   "aws-sm",
			wantDest:   "aws-dest-1",
			wantMount:  "kv-v2",
			wantSecret: "prod/app/database/credentials",
			wantErr:    false,
		},
		{
			name:       "github destination type",
			id:         "gh/dest/gh-dest-1/mount/kv/secret/token",
			wantType:   "gh",
			wantDest:   "gh-dest-1",
			wantMount:  "kv",
			wantSecret: "token",
			wantErr:    false,
		},
		{
			name:    "invalid format - missing parts",
			id:      "gcp-sm/dest/gcp-secret-manager/mount/kvv2-gcp3",
			wantErr: true,
		},
		{
			name:    "invalid format - wrong structure",
			id:      "gcp-sm-gcp-secret-manager-kvv2-gcp3-token",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields, err := syncAssociationFieldsFromID(tt.id)

			if tt.wantErr {
				if err == nil {
					t.Errorf("syncAssociationFieldsFromID() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("syncAssociationFieldsFromID() unexpected error = %v", err)
				return
			}

			if len(fields) != 4 {
				t.Errorf("syncAssociationFieldsFromID() returned %d fields, want 4", len(fields))
				return
			}

			gotType := fields[0]
			gotDest := fields[1]
			gotMount := fields[2]
			gotSecret := fields[3]

			if gotType != tt.wantType {
				t.Errorf("syncAssociationFieldsFromID() type = %v, want %v", gotType, tt.wantType)
			}
			if gotDest != tt.wantDest {
				t.Errorf("syncAssociationFieldsFromID() dest = %v, want %v", gotDest, tt.wantDest)
			}
			if gotMount != tt.wantMount {
				t.Errorf("syncAssociationFieldsFromID() mount = %v, want %v", gotMount, tt.wantMount)
			}
			if gotSecret != tt.wantSecret {
				t.Errorf("syncAssociationFieldsFromID() secret = %v, want %v", gotSecret, tt.wantSecret)
			}
		})
	}
}
