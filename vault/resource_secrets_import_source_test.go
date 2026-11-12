// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestSecretsImportAWSSource(t *testing.T) {
	name := acctest.RandomWithPrefix("import-source")
	mount := acctest.RandomWithPrefix("kvv2")
	resourceName := "vault_secrets_import_aws_source.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), secretsImportMinVersion)
		},
		Steps: []resource.TestStep{
			{
				Config: testSecretsImportAWSSource(name, mount, "us-east-1", `
  role_arn    = "arn:aws:iam::123456789012:role/VaultSecretsImport"
  external_id = "ext-123"
  filter      = "\"prod\" in Secret.Name"`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "ext-123"),
					resource.TestCheckResourceAttr(resourceName, fieldImportFilter, `"prod" in Secret.Name`),
					resource.TestCheckResourceAttr(resourceName, fieldDestinationMount, mount),
					resource.TestCheckResourceAttr(resourceName, fieldAuthMode, "host_credentials_assume_role"),
					resource.TestCheckResourceAttrSet(resourceName, fieldImportCreatedAt),
				),
			},
			{
				// Removing attributes from the config must clear them in Vault.
				Config: testSecretsImportAWSSource(name, mount, "ap-southeast-2", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "ap-southeast-2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, ""),
					resource.TestCheckResourceAttr(resourceName, fieldImportFilter, ""),
					resource.TestCheckResourceAttr(resourceName, fieldAuthMode, "host_credentials"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, fieldImportUpdatedAt),
		},
	})
}

func TestSecretsImportAWSSource_StaticCredentials(t *testing.T) {
	name := acctest.RandomWithPrefix("import-source")
	mount := acctest.RandomWithPrefix("kvv2")
	resourceName := "vault_secrets_import_aws_source.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), secretsImportMinVersion)
		},
		Steps: []resource.TestStep{
			{
				Config: testSecretsImportAWSSource(name, mount, "us-east-1", `
  access_key_id     = "AKIAEXAMPLE"
  secret_access_key = "secret-example"`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, fieldAuthMode, "static_credentials"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKeyID, "AKIAEXAMPLE"),
				),
			},
			// Vault masks static credentials on read, so they cannot be imported.
			testutil.GetImportTestStep(resourceName, false, nil, fieldImportUpdatedAt,
				consts.FieldAccessKeyID, consts.FieldSecretAccessKey),
		},
	})
}

func TestSecretsImport_MissingSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), secretsImportMinVersion)
		},
		Steps: []resource.TestStep{
			{
				Config: `
data "vault_secrets_import_plan" "test" {
  type = "aws-sm"
  name = "does-not-exist"
}
`,
				ExpectError: regexp.MustCompile(`error running secrets import plan for source "aws-sm/does-not-exist"`),
			},
			{
				Config: `
resource "vault_secrets_import_apply" "test" {
  type = "aws-sm"
  name = "does-not-exist"
}
`,
				ExpectError: regexp.MustCompile(`error running secrets import apply for source "aws-sm/does-not-exist"`),
			},
		},
	})
}

func testSecretsImportAWSSource(name, mount, region, extra string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kvv2" {
  path    = "%s"
  type    = "kv"
  options = { version = "2" }
}

resource "vault_secrets_import_aws_source" "test" {
  name              = "%s"
  region            = "%s"
  destination_mount = vault_mount.kvv2.path
%s
}
`, mount, name, region, extra)
}

func TestParseImportResponse(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]interface{}
		operation string
		want      *importResult
	}{
		{
			name:      "apply reads imported",
			operation: importOperationApply,
			data: map[string]interface{}{
				fieldAuthMode:         "workload_identity_federation",
				fieldDestinationMount: "kvv2",
				fieldScannedCount:     json.Number("3"),
				fieldImported:         []interface{}{"aws/a"},
				fieldIgnored:          []interface{}{"staging/b"},
				fieldFailed:           map[string]interface{}{"aws/c": "DecryptionFailure"},
			},
			want: &importResult{
				AuthMode:         "workload_identity_federation",
				DestinationMount: "kvv2",
				ScannedCount:     3,
				Secrets:          []string{"aws/a"},
				Ignored:          []string{"staging/b"},
				Failed:           map[string]string{"aws/c": "DecryptionFailure"},
			},
		},
		{
			name:      "plan reads would_import",
			operation: importOperationPlan,
			data: map[string]interface{}{
				fieldScannedCount: json.Number("2"),
				fieldWouldImport:  []interface{}{"aws/a", "aws/b"},
				fieldImported:     []interface{}{"ignored"},
			},
			want: &importResult{
				ScannedCount: 2,
				Secrets:      []string{"aws/a", "aws/b"},
				Failed:       map[string]string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseImportResponse(tt.data, tt.operation)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	_, err := parseImportResponse(map[string]interface{}{fieldScannedCount: "x"}, importOperationApply)
	require.Error(t, err)
}
