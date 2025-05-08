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

func TestAccKVSecretBackendV2(t *testing.T) {
	t.Parallel()
	resourceName := "vault_kv_secret_backend_v2.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKVSecretBackendV2Config(mount, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "5"),
					resource.TestCheckResourceAttr(resourceName, "delete_version_after", "3700"),
					resource.TestCheckResourceAttr(resourceName, "cas_required", "true"),
				),
			},
			{
				Config: testKVSecretBackendV2Config(mount, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "7"),
					resource.TestCheckResourceAttr(resourceName, "delete_version_after", "87550"),
					resource.TestCheckResourceAttr(resourceName, "cas_required", "true"),
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

func TestKVV2SecretNameFromPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		path      string
		want      string
		expectErr bool
	}{
		{
			name:      "non-prefixed secret name",
			path:      "cloud/data/dev-token",
			want:      "dev-token",
			expectErr: false,
		},
		{
			name:      "prefixed secret name",
			path:      "cloud/data/engineering/admin/token",
			want:      "engineering/admin/token",
			expectErr: false,
		},
		{
			name:      "invalid path",
			path:      "secret/random/value",
			want:      "",
			expectErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			name, err := getKVV2SecretNameFromPath(tt.path)
			if err == nil && tt.expectErr {
				t.Fatalf("expected error but got nil")
			}

			if name != tt.want {
				t.Fatalf("expected name %s, but got %s", tt.want, name)
			}
		})
	}
}

func TestKVV2SecretMountFromPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		path      string
		want      string
		expectErr bool
	}{
		{
			name:      "non-prefixed mount name",
			path:      "cloud-metadata/data/token",
			want:      "cloud-metadata",
			expectErr: false,
		},
		{
			name:      "prefixed secret name",
			path:      "cloud-metadata/vault/kv/data/token",
			want:      "cloud-metadata/vault/kv",
			expectErr: false,
		},
		{
			name:      "invalid path",
			path:      "secret/random/value",
			want:      "",
			expectErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mount, err := getKVV2SecretMountFromPath(tt.path)

			if err == nil && tt.expectErr {
				t.Fatalf("expected error but got nil")
			}

			if mount != tt.want {
				t.Fatalf("expected name %s, but got %s", tt.want, mount)
			}
		})
	}
}

func testKVSecretBackendV2Config(path string, isUpdate bool) string {
	ret := fmt.Sprintf(`
%s

`, kvV2MountConfig(path))

	if !isUpdate {
		ret += fmt.Sprintf(`
resource "vault_kv_secret_backend_v2" "test" {
  mount                = vault_mount.kvv2.path
  max_versions         = 5
  delete_version_after = 3700
  cas_required         = true
}`)
	} else {
		ret += fmt.Sprintf(`
resource "vault_kv_secret_backend_v2" "test" {
  mount                = vault_mount.kvv2.path
  max_versions         = 7
  delete_version_after = 87550
  cas_required         = true
}`)
	}
	return ret
}

func kvV2MountConfig(path string) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "kvv2" {
	path        = "%s"
	type        = "kv"
    options     = { version = "2" }
    description = "KV Version 2 secret engine mount"
}`, path)

	return ret
}
