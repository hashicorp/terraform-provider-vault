// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAWSSecretBackendStaticRole(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-aws-static")
	a, s := testutil.GetTestAWSCreds(t)
	resourceName := "vault_aws_secret_backend_static_role.role"
	username := testutil.SkipTestEnvUnset(t, "AWS_STATIC_USER")[0]

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAWSStaticReourceConfig(mount, a, s, username),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, "vault-static-roles-test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "3600"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

// TestAWSPathMatching tests the regular expression (and supporting function) that parses paths into backends and role names
func TestAWSPathMatching(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		backend string
		role    string
		isError bool
	}{
		{
			name:    "simple case",
			path:    "a/static-roles/c",
			backend: "a",
			role:    "c",
		},
		{
			name:    "multi-slash mount",
			path:    "a/b/c/static-roles/c",
			backend: "a/b/c",
			role:    "c",
		},
		{
			name:    "multi-slash role case",
			path:    "a/static-roles/c/d/e",
			backend: "a",
			role:    "c/d/e",
		},
		{
			name:    "empty slashes",
			path:    "a///static-roles/c",
			backend: "a//",
			role:    "c",
		},
		{
			name:    "complications",
			path:    "a/static-roles//static-roles/c",
			backend: "a/static-roles/",
			role:    "c",
		},
		{
			name:    "invalid no static-roles",
			path:    "a///static-role/c",
			isError: true,
		},
		{
			name:    "invalid empty",
			path:    "",
			isError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, r, e := parseAWSStaticRolePath(tc.path)
			if tc.isError && e == nil {
				t.Fatal("expected an error but didn't get one")
			} else if !tc.isError && e != nil {
				t.Fatalf("got an unexpected error: %s", e)
			}
			if b != tc.backend {
				t.Fatalf("mismatched backend: %s expected, %s actual", tc.backend, b)
			}
			if r != tc.role {
				t.Fatalf("mismatched role: %s expected, %s actual", tc.role, r)
			}
		})
	}
}

const testAWSStaticResource = `
resource "vault_aws_secret_backend" "aws" {
  path = "%s"
  description = "Obtain AWS credentials."
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_backend_static_role" "role" {
  backend = vault_aws_secret_backend.aws.path
  name = "test"
  username = "%s"
  rotation_period = "3600"
}`

func testAWSStaticReourceConfig(mount, access, secret, username string) string {
	return fmt.Sprintf(testAWSStaticResource, mount, access, secret, username)
}
