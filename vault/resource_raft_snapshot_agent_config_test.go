// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccRaftSnapshotAgentConfig_basic(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			testutil.TestEntPreCheck(t)
		},
		CheckDestroy: testAccRaftSnapshotAgentConfigCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "interval_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "path_prefix", "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "storage_type", "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "local_max_space", "4096"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_updated(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "interval_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "path_prefix", "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "storage_type", "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "local_max_space", "4096"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_aws(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "interval_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "path_prefix", "/path/in/bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "aws_s3_bucket", "my-bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "aws_s3_region", "us-east-1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "aws_access_key_id", "aws-access-key-id"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "aws_secret_access_key", "aws-secret-access-key"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "aws_session_token", "aws-session-token"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "aws_s3_enable_kms", "true"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.aws_backups", "aws_s3_kms_key", "alias/VaultBackupKMS"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_google(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", "interval_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", "path_prefix", "/path/in/bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", "storage_type", "google-gcs"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", "google_gcs_bucket", "my-bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.google_backups", "google_service_account_key", "{}"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_azure(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "interval_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "path_prefix", "/path/in/bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "storage_type", "azure-blob"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "azure_container_name", "my-bucket"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "azure_account_name", "azure-account-name"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "azure_account_key", "azure-account-key"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_backups", "azure_blob_environment", "azure-env"),
				),
			},
		},
	})
}

func TestAccRaftSnapshotAgentConfig_azureManagedIdentityWithAutoload(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			testutil.TestEntPreCheck(t)
		},
		CheckDestroy: testAccRaftSnapshotAgentConfigCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_azureManagedIdentityWithAutoload(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", "autoload_enabled", "true"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", "azure_client_id", "test-client-id"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.azure_managed_identity", "azure_auth_mode", "managed"),
				),
			},
		},
	})
}

func TestAccRaftSnapshotAgentConfig_import(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			testutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccRaftSnapshotAgentConfigCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "interval_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "path_prefix", "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "storage_type", "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "local_max_space", "4096"),
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

func testAccRaftSnapshotAgentConfigCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_raft_snapshot_agent_config" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		snapshot, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if snapshot != nil {
			return fmt.Errorf("library %q still exists", rs.Primary.ID)
		}
	}
	return nil
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
  path_prefix = "/path/in/bucket"
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
  path_prefix = "/path/in/bucket"
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
  path_prefix = "/path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_account_key = "azure-account-key"
  azure_blob_environment = "azure-env"
}`, name)
}

func testAccRaftSnapshotAgentConfig_azureManagedIdentityWithAutoload(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "azure_managed_identity" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "/path/in/bucket"
  storage_type = "azure-blob"
  azure_container_name = "my-bucket"
  azure_account_name = "azure-account-name"
  azure_blob_environment = "azure-env"
  autoload_enabled = true
  azure_auth_mode = "managed"
  azure_client_id = "test-client-id"
}`, name)
}
