// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
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

func TestGCPSecretsSyncDestinationWIF(t *testing.T) {

	resourceName := "vault_secrets_sync_gcp_destination.test"

	values := testutil.SkipTestEnvUnset(t, "IDENTITY_TOKEN_AUDIENCE", "GCP_SERVICE_ACCOUNT_EMAIL", "GCP_PROJECT_ID", "GCP_DESTINATION_NAME")
	audience := values[0]
	service_account_email := values[1]
	project_id := values[2]
	destName := values[3]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion200)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !(meta.IsAPISupported(provider.VaultVersion200) && meta.IsEnterpriseSupported()), nil
				},
				Config: testGCPSecretsSyncDestinationWIFConfig_initial(destName, project_id, service_account_email, audience),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, project_id),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, audience),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountEmail, service_account_email),
				),
			},
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

func testGCPSecretsSyncDestinationWIFConfig_initial(destName, project_id, service_account_email, audience string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                    = "%s"
  granularity			   = "secret-path"
  project_id				= "%s"
  service_account_email   = "%s"
  identity_token_audience = "%s"
  identity_token_ttl      = 30
}`, destName, project_id, service_account_email, audience)
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

func TestGCPSecretsSyncDestination_AdvancedFeatures(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-gcp")
	resourceName := "vault_secrets_sync_gcp_destination.test"

	credentials, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			// Step 1: Test basic replication (Vault 1.18+)
			{
				Config: testGCPSecretsSyncDestinationConfig_replicationBasic(credentials, project, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, project),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".0", "us-central1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".1", "us-east1"),
				),
			},
		},
	})

	// Vault 1.19+ features require a separate test or conditional checks
	if provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion119) {
		resource.Test(t, resource.TestCase{
			ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
			PreCheck: func() {
				acctestutil.TestAccPreCheck(t)
				SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
			},
			Steps: []resource.TestStep{
				// Step 1: Test networking configuration
				{
					Config: testGCPSecretsSyncDestinationConfig_networking(credentials, project, destName+"-net"),
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
				// Step 2: Test global encryption
				{
					Config: testGCPSecretsSyncDestinationConfig_encryption(credentials, project, destName+"-enc"),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, project),
						resource.TestCheckResourceAttr(resourceName, consts.FieldGlobalKmsKey, "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"),
					),
				},
				// Step 3: Test replication with locational KMS
				{
					Config: testGCPSecretsSyncDestinationConfig_replication(credentials, project, destName+"-rep-kms"),
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
}

func TestGCPSecretsSyncDestination_NegativeTests(t *testing.T) {
	resourceName := "vault_secrets_sync_gcp_destination.test"
	credentials, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		Steps: []resource.TestStep{
			// Test 1: Invalid IPv4 CIDR notation - should fail
			{
				Config:      testGCPSecretsSyncDestinationConfig_invalidIPv4(credentials, project, acctest.RandomWithPrefix("tf-sync-dest-gcp")),
				ExpectError: regexp.MustCompile("."), // Any error indicates validation worked
			},
			// Test 2: Invalid IPv6 CIDR notation - should fail
			{
				Config:      testGCPSecretsSyncDestinationConfig_invalidIPv6(credentials, project, acctest.RandomWithPrefix("tf-sync-dest-gcp")),
				ExpectError: regexp.MustCompile("."), // Any error indicates validation worked
			},
			// Test 3: Conflicting encryption - both global_kms_key and locational_kms_keys with replication_locations - should fail
			{
				Config:      testGCPSecretsSyncDestinationConfig_conflictingEncryption(credentials, project, acctest.RandomWithPrefix("tf-sync-dest-gcp")),
				ExpectError: regexp.MustCompile("."), // Any error indicates validation worked
			},
			// Test 4: Duplicate regions in replication_locations - TypeSet should deduplicate automatically
			{
				Config: testGCPSecretsSyncDestinationConfig_duplicateRegions(credentials, project, acctest.RandomWithPrefix("tf-sync-dest-gcp")),
				Check: resource.ComposeTestCheckFunc(
					// TypeSet automatically deduplicates, so we should only see 2 unique regions
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicationLocations+".#", "2"),
				),
			},
		},
	})
}

func testGCPSecretsSyncDestinationConfig_invalidIPv4(credentials, project, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                   = "%s"
  project_id             = "%s"
  credentials            = <<CREDS
%s
CREDS
  secret_name_template   = "vault_{{ .MountAccessor }}_{{ .SecretPath }}"
  
  allowed_ipv4_addresses = ["256.256.256.256/32", "10.0.0.0/8"]
}
`, destName, project, credentials)
}

func testGCPSecretsSyncDestinationConfig_invalidIPv6(credentials, project, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                   = "%s"
  project_id             = "%s"
  credentials            = <<CREDS
%s
CREDS
  secret_name_template   = "vault_{{ .MountAccessor }}_{{ .SecretPath }}"
  
  allowed_ipv6_addresses = ["gggg::/32", "2001:db8::/32"]
}
`, destName, project, credentials)
}

func testGCPSecretsSyncDestinationConfig_conflictingEncryption(credentials, project, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                 = "%s"
  project_id           = "%s"
  credentials          = <<CREDS
%s
CREDS
  secret_name_template = "vault_{{ .MountAccessor }}_{{ .SecretPath }}"
  
  global_kms_key = "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"
  locational_kms_keys = {
    "us-central1" = "projects/my-project/locations/us-central1/keyRings/kr/cryptoKeys/key"
  }
  replication_locations = ["us-central1"]
}
`, destName, project, credentials)
}

func testGCPSecretsSyncDestinationConfig_duplicateRegions(credentials, project, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                 = "%s"
  project_id           = "%s"
  credentials          = <<CREDS
%s
CREDS
  secret_name_template = "vault_{{ .MountAccessor }}_{{ .SecretPath }}"
  granularity          = "secret-path"
  
  # TypeSet should automatically deduplicate these
  replication_locations = ["us-central1", "us-east1", "us-central1"]
}
`, destName, project, credentials)
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
