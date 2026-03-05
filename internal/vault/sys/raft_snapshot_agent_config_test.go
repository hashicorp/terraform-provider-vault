// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccRaftSnapshotAgentConfig_basic(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			acctestutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldIntervalSeconds, "3600"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldRetain, "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldPathPrefix, "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldFilePrefix, "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldStorageType, "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldLocalMaxSpace, "4096"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_updated(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldIntervalSeconds, "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldRetain, "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldPathPrefix, "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldFilePrefix, "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldStorageType, "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldLocalMaxSpace, "4096"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_aws(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldIntervalSeconds, "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldRetain, "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldPathPrefix, "path/in/bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldFilePrefix, "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldAWSS3Bucket, "my-bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldAWSS3Region, "us-east-1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldAWSAccessKeyID, "aws-access-key-id"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldAWSSecretAccessKey, "aws-secret-access-key"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldAWSSessionToken, "aws-session-token"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldAWSS3EnableKMS, "true"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", consts.FieldAWSS3KMSKey, "alias/VaultBackupKMS"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_google(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", consts.FieldIntervalSeconds, "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", consts.FieldRetain, "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", consts.FieldPathPrefix, "path/in/bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", consts.FieldFilePrefix, "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", consts.FieldStorageType, "google-gcs"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", consts.FieldGoogleGCSBucket, "my-bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", consts.FieldGoogleServiceAccountKey, "{}"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_azure(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldIntervalSeconds, "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldRetain, "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldPathPrefix, "path/in/bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldFilePrefix, "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldStorageType, "azure-blob"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldAzureContainerName, "my-bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldAzureAccountName, "azure-account-name"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldAzureAccountKey, "azure-account-key"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldAzureBlobEnvironment, "azure-env"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", consts.FieldAzureAuthMode, "shared"),
				),
			},
		},
	})
}

// TestAccRaftSnapshotAgentConfig_azureManagedIdentity tests Azure Managed Identity
// authentication with and without autoload feature.
// Step 1: Tests azure_auth_mode and azure_client_id (Requires Vault Enterprise 1.18.0+)
// Step 2: Tests autoload_enabled with Azure Managed Identity (Requires Vault Enterprise 1.21.0+)
func TestAccRaftSnapshotAgentConfig_azureManagedIdentity(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_azureManagedIdentity(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", consts.FieldAzureClientID, "test-client-id"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", consts.FieldAzureAuthMode, "managed"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					acctestutil.PreCheck(t)
					pm := acctestutil.TestProvider.Meta().(*provider.ProviderMeta)
					return !pm.IsAPISupported(provider.VaultVersion121), nil
				},
				Config: testAccRaftSnapshotAgentConfig_azureManagedIdentityWithAutoload(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", consts.FieldAutoloadEnabled, "true"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", consts.FieldAzureClientID, "test-client-id"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", consts.FieldAzureAuthMode, "managed"),
				),
			},
		},
	})
}

// TestAccRaftSnapshotAgentConfig_azureEnvironment tests Azure Environment authentication.
// Requires Vault Enterprise 1.18.0+
func TestAccRaftSnapshotAgentConfig_azureEnvironment(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_azureEnvironment(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_environment", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_environment", consts.FieldAzureAuthMode, "environment"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_environment", consts.FieldStorageType, "azure-blob"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_environment", consts.FieldAzureContainerName, "my-bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_environment", consts.FieldAzureAccountName, "azure-account-name"),
				),
			},
		},
	})
}

// TestAccRaftSnapshotAgentConfig_azureAuthModeNegative tests negative scenarios
// for Azure authentication modes to ensure proper validation.
// Requires Vault Enterprise 1.18.0+
func TestAccRaftSnapshotAgentConfig_azureAuthModeNegative(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccRaftSnapshotAgentConfig_azureSharedMissingKey(name),
				ExpectError: regexp.MustCompile("azure_account_key is required"),
			},
			{
				Config:      testAccRaftSnapshotAgentConfig_azureManagedMissingClientID(name),
				ExpectError: regexp.MustCompile("azure_client_id is required"),
			},
			{
				Config:      testAccRaftSnapshotAgentConfig_azureInvalidAuthMode(name),
				ExpectError: regexp.MustCompile("azure_auth_mode must be one of"),
			},
		},
	})
}

func TestAccRaftSnapshotAgentConfig_import(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldIntervalSeconds, "3600"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldRetain, "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldPathPrefix, "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldFilePrefix, "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldStorageType, "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", consts.FieldLocalMaxSpace, "4096"),
				),
			},
			{
				ResourceName:      "vault_raft_snapshot_agent_config.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccRaftSnapshotAgentConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "test" {
  name = "%s"
  interval_seconds = 3600
  retain = 1
  path_prefix = "/tmp"
  storage_type = "local"
  local_max_space = 4096
}`, name)
}

func testAccRaftSnapshotAgentConfig_updated(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "test" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "/tmp"
  storage_type = "local"
  local_max_space = 4096
}`, name)
}

func testAccRaftSnapshotAgentConfig_aws(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "aws_backups" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "aws-s3"
  aws_s3_bucket = "my-bucket"
  aws_s3_region = "us-east-1"
  aws_access_key_id = "aws-access-key-id"
  aws_secret_access_key = "aws-secret-access-key"
  aws_session_token = "aws-session-token"
  aws_s3_enable_kms = true
  aws_s3_kms_key = "alias/VaultBackupKMS"
}`, name)
}

func testAccRaftSnapshotAgentConfig_google(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "google_backups" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "google-gcs"
  google_gcs_bucket = "my-bucket"
  google_service_account_key = "{}"
}`, name)
}

func testAccRaftSnapshotAgentConfig_azure(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "azure_backups" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_account_key = "azure-account-key"
  azure_blob_environment = "azure-env"
  azure_auth_mode = "shared"
}`, name)
}

func testAccRaftSnapshotAgentConfig_azureManagedIdentity(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "azure_managed_identity" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_blob_environment = "azure-env"
  azure_auth_mode = "managed"
  azure_client_id = "test-client-id"
}`, name)
}

func testAccRaftSnapshotAgentConfig_azureEnvironment(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "azure_environment" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_blob_environment = "azure-env"
  azure_auth_mode = "environment"
}`, name)
}

func testAccRaftSnapshotAgentConfig_azureSharedMissingKey(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "azure_shared_missing_key" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_blob_environment = "azure-env"
  azure_auth_mode = "shared"
  # Missing azure_account_key - should cause error
}`, name)
}

func testAccRaftSnapshotAgentConfig_azureManagedMissingClientID(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "azure_managed_missing_client_id" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_blob_environment = "azure-env"
  azure_auth_mode = "managed"
  # Missing azure_client_id - should cause error
}`, name)
}

func testAccRaftSnapshotAgentConfig_azureInvalidAuthMode(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "azure_invalid_auth_mode" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_blob_environment = "azure-env"
  azure_auth_mode = "invalid-mode"
}`, name)
}

func testAccRaftSnapshotAgentConfig_azureManagedIdentityWithAutoload(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "azure_managed_identity" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_blob_environment = "azure-env"
  autoload_enabled = true
  azure_auth_mode = "managed"
  azure_client_id = "test-client-id"
}`, name)
}
