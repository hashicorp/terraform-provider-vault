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

// TestSyncAssociationFieldsFromID_NewFormat tests the new length-based ID format
func TestSyncAssociationFieldsFromID_NewFormat(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		want      []string
		wantError bool
	}{
		{
			name: "basic new format",
			id:   "7,8,2,5:aws-kms:my-mount:kv:token",
			want: []string{"aws-kms", "my-mount", "kv", "token"},
		},
		{
			name: "values with keywords",
			id:   "6,11,2,6:gh-app:dest-secret:kv:secret",
			want: []string{"gh-app", "dest-secret", "kv", "secret"},
		},
		{
			name: "values with mount keyword",
			id:   "3,8,2,10:aws:my-mount:kv:mount-test",
			want: []string{"aws", "my-mount", "kv", "mount-test"},
		},
		{
			name: "values with colons",
			id:   "10,12,5,16:aws:kms:v2:dest:name:v2:kv/v2:secret:name:test",
			want: []string{"aws:kms:v2", "dest:name:v2", "kv/v2", "secret:name:test"},
		},
		{
			name: "empty field values",
			id:   "0,0,0,0::::",
			want: []string{"", "", "", ""},
		},
		{
			name: "single character values",
			id:   "1,1,1,1:a:b:c:d",
			want: []string{"a", "b", "c", "d"},
		},
		{
			name: "long values",
			id:   "19,29,15,26:very-long-dest-type:this-is-a-very-long-dest-name:long-mount-path:very-long-secret-name-here",
			want: []string{"very-long-dest-type", "this-is-a-very-long-dest-name", "long-mount-path", "very-long-secret-name-here"},
		},
		{
			name:      "invalid format - missing colon",
			id:        "7,8,2,5aws-kms:my-mount:kv:token",
			wantError: true,
		},
		{
			name:      "invalid format - wrong number of lengths",
			id:        "7,8,2:aws-kms:my-mount:kv:token",
			wantError: true,
		},
		{
			name:      "invalid format - non-numeric length",
			id:        "7,abc,2,5:aws-kms:my-mount:kv:token",
			wantError: true,
		},
		{
			name:      "invalid format - negative length",
			id:        "7,-8,2,5:aws-kms:my-mount:kv:token",
			wantError: true,
		},
		{
			name:      "invalid format - missing separator between values",
			id:        "7,8,2,5:aws-kmsmy-mount:kv:token",
			wantError: true,
		},
		{
			name:      "invalid format - trailing data",
			id:        "7,8,2,5:aws-kms:my-mount:kv:token:extra",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := syncAssociationFieldsFromID(tt.id)
			if tt.wantError {
				if err == nil {
					t.Errorf("syncAssociationFieldsFromID() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("syncAssociationFieldsFromID() unexpected error: %v", err)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("syncAssociationFieldsFromID() got %d fields, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("syncAssociationFieldsFromID() field[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestSyncAssociationFieldsFromID_OldFormat tests backward compatibility with old format
func TestSyncAssociationFieldsFromID_OldFormat(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		want      []string
		wantError bool
	}{
		{
			name: "basic old format",
			id:   "aws-kms/dest/my-dest/mount/kv/secret/token",
			want: []string{"aws-kms", "my-dest", "kv", "token"},
		},
		{
			name: "old format with hyphens",
			id:   "gh-app/dest/gh-dest-1/mount/kv-v2/secret/my-token",
			want: []string{"gh-app", "gh-dest-1", "kv-v2", "my-token"},
		},
		{
			name:      "old format - invalid regex",
			id:        "aws-kms/dest/my-dest/mount/kv",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := syncAssociationFieldsFromID(tt.id)
			if tt.wantError {
				if err == nil {
					t.Errorf("syncAssociationFieldsFromID() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("syncAssociationFieldsFromID() unexpected error: %v", err)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("syncAssociationFieldsFromID() got %d fields, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("syncAssociationFieldsFromID() field[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestIsLengthBasedIDFormat tests the format detection helper
func TestIsLengthBasedIDFormat(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{
			name: "length-based format - starts with digit",
			id:   "7,8,2,5:aws-kms:my-mount:kv:token",
			want: true,
		},
		{
			name: "old format - starts with letter",
			id:   "aws-kms/dest/my-dest/mount/kv/secret/token",
			want: false,
		},
		{
			name: "empty string",
			id:   "",
			want: false,
		},
		{
			name: "starts with zero",
			id:   "0,0,0,0::::",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLengthBasedIDFormat(tt.id)
			if got != tt.want {
				t.Errorf("isLengthBasedIDFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseLengthBasedID tests the length-based ID parser directly
func TestParseLengthBasedID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		want      []string
		wantError bool
	}{
		{
			name: "valid format",
			id:   "7,8,2,5:aws-kms:my-mount:kv:token",
			want: []string{"aws-kms", "my-mount", "kv", "token"},
		},
		{
			name: "with special characters",
			id:   "10,15,5,12:aws-kms-v2:dest_with-chars:kv/v2:secret@name!",
			want: []string{"aws-kms-v2", "dest_with-chars", "kv/v2", "secret@name!"},
		},
		{
			name: "with colons in values",
			id:   "10,12,5,16:aws:kms:v2:dest:name:v2:kv/v2:secret:name:test",
			want: []string{"aws:kms:v2", "dest:name:v2", "kv/v2", "secret:name:test"},
		},
		{
			name:      "missing colon separator",
			id:        "7,8,2,5aws-kms:my-mount:kv:token",
			wantError: true,
		},
		{
			name:      "too many length values",
			id:        "7,8,2,5,6:aws-kms:my-mount:kv:token",
			wantError: true,
		},
		{
			name:      "too few length values",
			id:        "7,8,2:aws-kms:my-mount:kv:token",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLengthBasedID(tt.id)
			if tt.wantError {
				if err == nil {
					t.Errorf("parseLengthBasedID() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("parseLengthBasedID() unexpected error: %v", err)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("parseLengthBasedID() got %d fields, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseLengthBasedID() field[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
