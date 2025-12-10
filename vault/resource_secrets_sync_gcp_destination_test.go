// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestGCPSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-gcp")

	resourceName := "vault_secrets_sync_gcp_destination.test"

	credentials, _ := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretsSyncDestinationConfig_initial(credentials, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentials, credentials),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, gcpSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, "gcp-project-id"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
				),
			},
			{
				Config: testGCPSecretsSyncDestinationConfig_updated(credentials, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentials, credentials),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, secretsKeyTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-key"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, gcpSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, "gcp-project-id-updated"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.baz", "bux"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldCredentials),
		},
	})
}

func testGCPSecretsSyncDestinationConfig_initial(credentials, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name          = "%s"
  project_id    = "gcp-project-id"
  credentials   = <<CREDS
%sCREDS
  %s
}
`, destName, credentials, testSecretsSyncDestinationCommonConfig(templ, false, true, false))

	return ret
}

func testGCPSecretsSyncDestinationConfig_updated(credentials, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name          = "%s"
  project_id    = "gcp-project-id-updated"
  credentials   = <<CREDS
%sCREDS
  %s
}
`, destName, credentials, testSecretsSyncDestinationCommonConfig(templ, true, true, true))

	return ret
}

func TestGCPSecretsSyncDestination_NetworkingAndEncryption(t *testing.T) {
	resourceName := "vault_secrets_sync_gcp_destination.test"

	credentials, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretsSyncDestinationConfig_networking(credentials, project, acctest.RandomWithPrefix("tf-sync-dest-gcp-net")),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, project),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".0", "10.0.0.0/8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".1", "192.168.0.0/16"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".0", "2001:db8::/32"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".0", "443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".1", "8443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "false"),
				),
			},
		},
	})
}

func TestGCPSecretsSyncDestination_Encryption(t *testing.T) {
	resourceName := "vault_secrets_sync_gcp_destination.test"

	credentials, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretsSyncDestinationConfig_encryption(credentials, project, acctest.RandomWithPrefix("tf-sync-dest-gcp-enc")),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, project),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGlobalKmsKey, "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"),
				),
			},
		},
	})
}

func TestGCPSecretsSyncDestination_Replication(t *testing.T) {
	resourceName := "vault_secrets_sync_gcp_destination.test"

	credentials, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretsSyncDestinationConfig_replicationBasic(credentials, project, acctest.RandomWithPrefix("tf-sync-dest-gcp-rep")),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, project),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".0", "us-central1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".1", "us-east1"),
				),
			},
		},
	})
}

func TestGCPSecretsSyncDestination_ReplicationWithLocationalKMS(t *testing.T) {
	resourceName := "vault_secrets_sync_gcp_destination.test"

	credentials, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretsSyncDestinationConfig_replication(credentials, project, acctest.RandomWithPrefix("tf-sync-dest-gcp-rep-kms")),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, project),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocationalKmsKeys+".%", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocationalKmsKeys+".us-central1", "projects/my-project/locations/us-central1/keyRings/kr/cryptoKeys/key"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocationalKmsKeys+".us-east1", "projects/my-project/locations/us-east1/keyRings/kr/cryptoKeys/key"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".0", "us-central1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".1", "us-east1"),
				),
			},
		},
	})
}

func testGCPSecretsSyncDestinationConfig_networking(credentials, project, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                      = "%s"
  project_id                = "%s"
  credentials               = <<CREDS
%s
CREDS
  secret_name_template      = "vault_{{ .MountAccessor }}_{{ .SecretPath }}"
  granularity               = "secret-path"
  
  allowed_ipv4_addresses    = ["10.0.0.0/8", "192.168.0.0/16"]
  allowed_ipv6_addresses    = ["2001:db8::/32"]
  allowed_ports             = [443, 8443]
  disable_strict_networking = false
}
`, destName, project, credentials)
}

func testGCPSecretsSyncDestinationConfig_encryption(credentials, project, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                 = "%s"
  project_id           = "%s"
  credentials          = <<CREDS
%s
CREDS
  secret_name_template = "vault_{{ .MountAccessor }}_{{ .SecretPath }}"
  granularity          = "secret-path"
  
  global_kms_key       = "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"
}
`, destName, project, credentials)
}

func testGCPSecretsSyncDestinationConfig_replicationBasic(credentials, project, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                 = "%s"
  project_id           = "%s"
  credentials          = <<CREDS
%s
CREDS
  secret_name_template = "vault_{{ .MountAccessor }}_{{ .SecretPath }}"
  granularity          = "secret-path"
  
  replication_locations = ["us-central1", "us-east1"]
}
`, destName, project, credentials)
}

func testGCPSecretsSyncDestinationConfig_replication(credentials, project, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                 = "%s"
  project_id           = "%s"
  credentials          = <<CREDS
%s
CREDS
  secret_name_template = "vault_{{ .MountAccessor }}_{{ .SecretPath }}_{{ .SecretKey }}"
  granularity          = "secret-key"
  
  locational_kms_keys = {
    "us-central1" = "projects/my-project/locations/us-central1/keyRings/kr/cryptoKeys/key"
    "us-east1"    = "projects/my-project/locations/us-east1/keyRings/kr/cryptoKeys/key"
  }
  replication_locations = ["us-central1", "us-east1"]
}
`, destName, project, credentials)
}
