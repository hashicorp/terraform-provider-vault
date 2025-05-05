// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPKISecretBackendAcmeEab(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_acme_eab"
	resourceBackend := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				// Test EAB creation without a role and issuer
				Config: testAccPKISecretBackendEAB(backend, "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldIssuer, ""),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldRole, ""),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldEabId),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldKeyType, "hs"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAcmeDirectory, "acme/directory"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldEabKey),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldsCreatedOn),
				),
			},
			{
				// Test EAB creation with role and issuer
				Config: testAccPKISecretBackendEAB(backend, "test-issuer", "test-role"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldIssuer, "test-issuer"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldRole, "test-role"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldEabId),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldKeyType, "hs"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAcmeDirectory, "issuer/test-issuer/roles/test-role/acme/directory"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldEabKey),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldsCreatedOn),
				),
			},
			{
				// Test EAB creation with just an issuer
				Config: testAccPKISecretBackendEAB(backend, "test-issuer", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldIssuer, "test-issuer"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldRole, ""),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldEabId),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldKeyType, "hs"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAcmeDirectory, "issuer/test-issuer/acme/directory"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldEabKey),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldsCreatedOn),
				),
			},
			{
				// Test EAB creation with just a role
				Config: testAccPKISecretBackendEAB(backend, "", "test-role"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldIssuer, ""),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldRole, "test-role"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldEabId),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldKeyType, "hs"),
					resource.TestCheckResourceAttr(resourceBackend, consts.FieldAcmeDirectory, "roles/test-role/acme/directory"),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldEabKey),
					resource.TestCheckResourceAttrSet(resourceBackend, consts.FieldsCreatedOn),
				),
			},
			{
				// Test EAB deletion
				Config:  testAccPKISecretBackendEAB(backend, "", ""),
				Destroy: true,
			},
		},
	})

}

func testAccPKISecretBackendEAB(path, issuer, role string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_role" "test" {
  backend = vault_mount.test.path
  name = "test-role"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
  issuer_name = "test-issuer"
}

resource "vault_pki_secret_backend_acme_eab" "test" {
  backend = vault_mount.test.path
  issuer = "%s"
  role = "%s"
}
`, path, issuer, role)
}

func Test_pkiSecretBackendComputeAcmeDirectoryPath(t *testing.T) {
	type args struct {
		backend string
		issuer  string
		role    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"issuer-with-role", args{"pki", "my-issuer", "my-role"}, "pki/issuer/my-issuer/roles/my-role/acme/new-eab"},
		{"only-issuer", args{"pki", "my-issuer", ""}, "pki/issuer/my-issuer/acme/new-eab"},
		{"only-role", args{"pki", "", "my-role"}, "pki/roles/my-role/acme/new-eab"},
		{"only-backend", args{"pki", "", ""}, "pki/acme/new-eab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pkiSecretBackendComputeAcmeDirectoryPath(tt.args.backend, tt.args.issuer, tt.args.role); got != tt.want {
				t.Errorf("pkiSecretBackendComputeAcmeDirectoryPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
