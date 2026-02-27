// Copyright IBM Corp. 2016, 2025
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

func TestAzureSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-azure")

	resourceName := "vault_secrets_sync_azure_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"AZURE_KEY_VAULT_URI",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_TENANT_ID",
	)
	keyVaultURI := values[0]
	clientID := values[1]
	clientSecret := values[2]
	tenantID := values[3]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretsSyncDestinationConfig_initial(keyVaultURI, clientID, clientSecret, tenantID, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, clientSecret),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, clientID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, tenantID),
					resource.TestCheckResourceAttr(resourceName, fieldKeyVaultURI, keyVaultURI),
					resource.TestCheckResourceAttr(resourceName, fieldCloud, "cloud"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
				),
			},
			{
				Config: testAzureSecretsSyncDestinationConfig_updated(keyVaultURI, clientID, clientSecret, tenantID, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, clientSecret),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, clientID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, tenantID),
					resource.TestCheckResourceAttr(resourceName, fieldKeyVaultURI, keyVaultURI),
					resource.TestCheckResourceAttr(resourceName, fieldCloud, "cloud"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, secretsKeyTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-key"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.baz", "bux"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldClientSecret,
			),
		},
	})
}

func testAzureSecretsSyncDestinationConfig_initial(keyVaultURI, clientID, clientSecret, tenantID, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_azure_destination" "test" {
  name                 = "%s"
  key_vault_uri        = "%s"
  client_id            = "%s"
  client_secret        = "%s"
  tenant_id            = "%s"
  %s
}
`, destName, keyVaultURI, clientID, clientSecret, tenantID, testSecretsSyncDestinationCommonConfig(templ, true, true, false))

	return ret
}

func testAzureSecretsSyncDestinationConfig_updated(keyVaultURI, clientID, clientSecret, tenantID, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_azure_destination" "test" {
  name                 = "%s"
  key_vault_uri        = "%s"
  client_id            = "%s"
  client_secret        = "%s"
  tenant_id            = "%s"
  %s
}
`, destName, keyVaultURI, clientID, clientSecret, tenantID, testSecretsSyncDestinationCommonConfig(templ, true, true, true))

	return ret
}

// TestAzureSecretsSyncDestination_NetworkingFields tests the networking configuration fields
// - Creating a destination with both IPv4 and IPv6 address restrictions
// - Updating the destination to remove IPv4 and modify IPv6 addresses and ports updated as well
func TestAzureSecretsSyncDestination_NetworkingFields(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-azure-net")

	resourceName := "vault_secrets_sync_azure_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"AZURE_KEY_VAULT_URI",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_TENANT_ID",
	)
	keyVaultURI := values[0]
	clientID := values[1]
	clientSecret := values[2]
	tenantID := values[3]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretsSyncDestinationConfig_networking(keyVaultURI, clientID, clientSecret, tenantID, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, clientID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, tenantID),
					resource.TestCheckResourceAttr(resourceName, fieldKeyVaultURI, keyVaultURI),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv4Addresses+".*", "192.168.1.0/24"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv4Addresses+".*", "10.0.0.0/8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv6Addresses+".*", "2001:db8::/32"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedPorts+".*", "443"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedPorts+".*", "8443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "false"),
				),
			},
			{
				Config: testAzureSecretsSyncDestinationConfig_networkingUpdated(keyVaultURI, clientID, clientSecret, tenantID, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, clientID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, tenantID),
					resource.TestCheckResourceAttr(resourceName, fieldKeyVaultURI, keyVaultURI),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-key"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv6Addresses+".*", "2001:db8::/32"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv6Addresses+".*", "2001:db8:1::/48"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedPorts+".*", "443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldClientSecret,
			),
		},
	})
}

func testAzureSecretsSyncDestinationConfig_networking(keyVaultURI, clientID, clientSecret, tenantID, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_azure_destination" "test" {
  name                       = "%s"
  key_vault_uri              = "%s"
  client_id                  = "%s"
  client_secret              = "%s"
  tenant_id                  = "%s"
  granularity                = "secret-path"
  
  allowed_ipv4_addresses     = ["192.168.1.0/24", "10.0.0.0/8"]
  allowed_ipv6_addresses     = ["2001:db8::/32"]
  allowed_ports              = [443, 8443]
  disable_strict_networking  = false
}
`, destName, keyVaultURI, clientID, clientSecret, tenantID)
}

func testAzureSecretsSyncDestinationConfig_networkingUpdated(keyVaultURI, clientID, clientSecret, tenantID, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_azure_destination" "test" {
  name                       = "%s"
  key_vault_uri              = "%s"
  client_id                  = "%s"
  client_secret              = "%s"
  tenant_id                  = "%s"
  granularity                = "secret-key"
  
  allowed_ipv6_addresses     = ["2001:db8::/32", "2001:db8:1::/48"]
  allowed_ports              = [443]
  disable_strict_networking  = true
}
`, destName, keyVaultURI, clientID, clientSecret, tenantID)
}

// TestAzureSecretsSyncDestination_InvalidFields tests validation of invalid field values
// TestAzureSecretsSyncDestination_InvalidFields tests validation of invalid field values for Vault 1.15+
func TestAzureSecretsSyncDestination_InvalidFields(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-azure-invalid")

	values := testutil.SkipTestEnvUnset(t,
		"AZURE_KEY_VAULT_URI",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_TENANT_ID",
	)
	keyVaultURI := values[0]
	clientID := values[1]
	clientSecret := values[2]
	tenantID := values[3]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config:      testAzureSecretsSyncDestinationConfig_invalidFields(keyVaultURI, clientID, clientSecret, tenantID, destName, "granularity"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|granularity|must be|secret-path|secret-key`),
			},
			{
				Config:      testAzureSecretsSyncDestinationConfig_invalidFields(keyVaultURI, clientID, clientSecret, tenantID, destName, "secret_name_template"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|template`),
			},
			{
				Config:      testAzureSecretsSyncDestinationConfig_invalidFields(keyVaultURI, clientID, clientSecret, tenantID, destName, "custom_tags"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|tags`),
			},
		},
	})
}

// TestAzureSecretsSyncDestination_InvalidNetworkingFields tests validation of invalid networking field values for Vault 1.19+
func TestAzureSecretsSyncDestination_InvalidNetworkingFields(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-azure-invalid-net")

	values := testutil.SkipTestEnvUnset(t,
		"AZURE_KEY_VAULT_URI",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_TENANT_ID",
	)
	keyVaultURI := values[0]
	clientID := values[1]
	clientSecret := values[2]
	tenantID := values[3]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config:      testAzureSecretsSyncDestinationConfig_invalidFields(keyVaultURI, clientID, clientSecret, tenantID, destName, "allowed_ipv4_addresses"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|ipv4|cidr|address`),
			},
			{
				Config:      testAzureSecretsSyncDestinationConfig_invalidFields(keyVaultURI, clientID, clientSecret, tenantID, destName, "allowed_ipv6_addresses"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|ipv6|cidr|address`),
			},
			{
				Config:      testAzureSecretsSyncDestinationConfig_invalidFields(keyVaultURI, clientID, clientSecret, tenantID, destName, "allowed_ports"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|port|range`),
			},
		},
	})
}

func testAzureSecretsSyncDestinationConfig_invalidFields(keyVaultURI, clientID, clientSecret, tenantID, destName, invalidField string) string {
	// Base configuration with valid values
	config := fmt.Sprintf(`
resource "vault_secrets_sync_azure_destination" "test" {
  name          = "%s"
  key_vault_uri = "%s"
  client_id     = "%s"
  client_secret = "%s"
  tenant_id     = "%s"`, destName, keyVaultURI, clientID, clientSecret, tenantID)

	// Add the specific invalid field based on the parameter
	switch invalidField {
	case "granularity":
		config += `
  granularity   = "invalid-granularity"`
	case "secret_name_template":
		config += `
  secret_name_template = "{{.InvalidTemplate}}"`
	case "custom_tags":
		config += `
  custom_tags = {
    "invalid key with spaces" = "value"
  }`
	case "allowed_ipv4_addresses":
		config += `
	 allowed_ipv4_addresses = ["999.999.999.999/24"]`
	case "allowed_ipv6_addresses":
		config += `
	 allowed_ipv6_addresses = ["gggg:hhhh:iiii:jjjj:kkkk:llll:mmmm:nnnn/128"]`
	case "allowed_ports":
		config += `
	 allowed_ports = [99999]`
	}

	config += `
}
`
	return config
}
