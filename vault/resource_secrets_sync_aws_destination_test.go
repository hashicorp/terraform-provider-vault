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

const (
	defaultSecretsSyncTemplate = "vault/{{ .MountAccessor }}/{{ .SecretPath }}"
	updatedSecretsSyncTemplate = "VAULT_{{ .MountAccessor | uppercase }}_{{ .SecretPath | uppercase }}"
)

func TestAWSSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws")

	resourceName := "vault_secrets_sync_aws_destination.test"

	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretsSyncDestinationConfig_initial(accessKey, secretKey, region, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "role-arn-test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "external-id-test"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
				),
			},
			{
				Config: testAWSSecretsSyncDestinationConfig_updated(accessKey, secretKey, region, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, secretsKeyTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-key"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "role-arn-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "external-id-updated"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.baz", "bux"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessKeyID,
				fieldSecretAccessKey,
				consts.FieldDisableStrictNetworking, // Vault API doesn't return false when not set
			),
		},
	})
}

func TestAWSSecretsSyncDestination_Networking(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-net")

	resourceName := "vault_secrets_sync_aws_destination.test"

	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretsSyncDestinationConfig_networking(accessKey, secretKey, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv4Addresses+".*", "192.168.1.0/24"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv4Addresses+".*", "10.0.0.0/8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv6Addresses+".*", "2001:db8::/32"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedPorts+".*", "443"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedPorts+".*", "8200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "false"),
				),
			},
			{
				Config: testAWSSecretsSyncDestinationConfig_networkingUpdated(accessKey, secretKey, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedIPv4Addresses+".*", "172.16.0.0/12"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedPorts+".*", "443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessKeyID,
				fieldSecretAccessKey,
				consts.FieldDisableStrictNetworking, // Vault API doesn't return the value during import
			),
		},
	})
}

func TestAWSSecretsSyncDestination_InvalidNetworkingParams(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-invalid")

	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion119), nil
				},
				// Test with invalid CIDR notation for IPv4
				Config:      testAWSSecretsSyncDestinationConfig_invalidIPv4(accessKey, secretKey, region, destName),
				ExpectError: regexp.MustCompile("invalid CIDR address|Error"),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion119), nil
				},
				// Test with invalid CIDR notation for IPv6
				Config:      testAWSSecretsSyncDestinationConfig_invalidIPv6(accessKey, secretKey, region, destName),
				ExpectError: regexp.MustCompile("invalid CIDR address|Error"),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion119), nil
				},
				// Test with invalid port (out of range)
				Config:      testAWSSecretsSyncDestinationConfig_invalidPort(accessKey, secretKey, region, destName),
				ExpectError: regexp.MustCompile("invalid port|Error"),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion119), nil
				},
				// Test that duplicates in sets are handled correctly (should not error)
				Config: testAWSSecretsSyncDestinationConfig_duplicates(accessKey, secretKey, region, destName),
				Check: resource.ComposeTestCheckFunc(
					// Verify that duplicates are removed - set should only have 2 unique IPs
					resource.TestCheckResourceAttr("vault_secrets_sync_aws_destination.test", consts.FieldAllowedIPv4Addresses+".#", "2"),
					resource.TestCheckTypeSetElemAttr("vault_secrets_sync_aws_destination.test", consts.FieldAllowedIPv4Addresses+".*", "198.51.100.0/24"),
					resource.TestCheckTypeSetElemAttr("vault_secrets_sync_aws_destination.test", consts.FieldAllowedIPv4Addresses+".*", "203.0.113.0/24"),
					// Verify that duplicate ports are removed - set should only have 2 unique ports
					resource.TestCheckResourceAttr("vault_secrets_sync_aws_destination.test", consts.FieldAllowedPorts+".#", "2"),
					resource.TestCheckTypeSetElemAttr("vault_secrets_sync_aws_destination.test", consts.FieldAllowedPorts+".*", "8080"),
					resource.TestCheckTypeSetElemAttr("vault_secrets_sync_aws_destination.test", consts.FieldAllowedPorts+".*", "9090"),
				),
			},
		},
	})
}

func testAWSSecretsSyncDestinationConfig_networking(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                        = "%s"
  access_key_id               = "%s"
  secret_access_key           = "%s"
  region                      = "%s"
  granularity                 = "secret-path"
  allowed_ipv4_addresses      = ["192.168.1.0/24", "10.0.0.0/8"]
  allowed_ipv6_addresses      = ["2001:db8::/32"]
  allowed_ports               = [443, 8200]
  disable_strict_networking   = false
}
`, destName, accessKey, secretKey, region)
}

func testAWSSecretsSyncDestinationConfig_networkingUpdated(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                        = "%s"
  access_key_id               = "%s"
  secret_access_key           = "%s"
  region                      = "%s"
  granularity                 = "secret-path"
  allowed_ipv4_addresses      = ["172.16.0.0/12"]
  allowed_ports               = [443]
  disable_strict_networking   = true
}
`, destName, accessKey, secretKey, region)
}

func testAWSSecretsSyncDestinationConfig_initial(accessKey, secretKey, region, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                  = "%s"
  access_key_id	        = "%s"
  secret_access_key     = "%s"
  region                = "%s"
  role_arn              = "role-arn-test"
  external_id           = "external-id-test"
  %s
}
`, destName, accessKey, secretKey, region, testSecretsSyncDestinationCommonConfig(templ, false, true, false))

	return ret
}

func testAWSSecretsSyncDestinationConfig_updated(accessKey, secretKey, region, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                  = "%s"
  access_key_id         = "%s"
  secret_access_key     = "%s"
  region                = "%s"
  role_arn              = "role-arn-updated"
  external_id           = "external-id-updated"
  %s
}
`, destName, accessKey, secretKey, region, testSecretsSyncDestinationCommonConfig(templ, true, true, true))

	return ret
}

func testAWSSecretsSyncDestinationConfig_invalidIPv4(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                   = "%s"
  access_key_id          = "%s"
  secret_access_key      = "%s"
  region                 = "%s"
  granularity            = "secret-path"
  allowed_ipv4_addresses = ["203.0.113.5"]  # Invalid: missing CIDR notation
}
`, destName, accessKey, secretKey, region)
}

func testAWSSecretsSyncDestinationConfig_invalidIPv6(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                   = "%s"
  access_key_id          = "%s"
  secret_access_key      = "%s"
  region                 = "%s"
  granularity            = "secret-path"
  allowed_ipv6_addresses = ["2001:db8:85a3:0000:0000:8a2e:0370:ZZZZ"]  # Invalid: missing CIDR notation
}
`, destName, accessKey, secretKey, region)
}

func testAWSSecretsSyncDestinationConfig_invalidPort(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name              = "%s"
  access_key_id     = "%s"
  secret_access_key = "%s"
  region            = "%s"
  granularity       = "secret-path"
  allowed_ports     = [70000]  # Invalid: port out of range (max 65535)
}
`, destName, accessKey, secretKey, region)
}

func testAWSSecretsSyncDestinationConfig_duplicates(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name              = "%s"
  access_key_id     = "%s"
  secret_access_key = "%s"
  region            = "%s"
  granularity       = "secret-path"
  # Intentionally include duplicates to verify TypeSet behavior
  allowed_ipv4_addresses = ["198.51.100.0/24", "203.0.113.0/24", "198.51.100.0/24", "203.0.113.0/24"]
  allowed_ports          = [8080, 9090, 8080, 9090]
}
`, destName, accessKey, secretKey, region)
}

// TestAWSSecretsSyncDestinationWIF tests WIF (Workload Identity Federation)
// fields for the AWS secrets sync destination.
//
// This test requires IDENTITY_TOKEN_AUDIENCE and ROLE_ARN environment variables
// to be set. It will be skipped if they are not present. To run locally:
//
//	TF_ACC=1 VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
//	  AWS_DEFAULT_REGION=us-east-1 \
//	  IDENTITY_TOKEN_AUDIENCE=<audience> ROLE_ARN=<role-arn> \
//	  go test ./vault/ -run 'TestAWSSecretsSyncDestinationWIF' -v -count=1
func TestAWSSecretsSyncDestinationWIF(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-wif")
	resourceName := "vault_secrets_sync_aws_destination.test"
	region := testutil.GetTestAWSRegion(t)
	values := testutil.SkipTestEnvUnset(t, "IDENTITY_TOKEN_AUDIENCE", "ROLE_ARN")
	audience := values[0]
	roleArn := values[1]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion122)
		},
		PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretsSyncDestinationWIFConfig(destName, region, audience, 30, roleArn),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, roleArn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "30"),
				),
			},
			{
				Config: testAWSSecretsSyncDestinationWIFConfig(destName, region, audience, 60, roleArn),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, roleArn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "60"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessKeyID,
				fieldSecretAccessKey,
				consts.FieldIdentityTokenAudience,
				consts.FieldIdentityTokenKey,
				consts.FieldDisableStrictNetworking,
			),
		},
	})
}

func testAWSSecretsSyncDestinationWIFConfig(destName, region, audience string, ttl int, roleArn string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                    = "%s"
  region                  = "%s"
  role_arn                = "%s"
  identity_token_audience = "%s"
  identity_token_ttl      = %d
  granularity             = "secret-path"
}`, destName, region, roleArn, audience, ttl)
}

func testSecretsSyncDestinationCommonConfig(templ string, withTemplate, withTags, update bool) string {
	ret := ""
	if withTemplate {
		ret += fmt.Sprintf(`
  secret_name_template = "%s"
`, templ)
	}

	if withTags && !update {
		ret += fmt.Sprintf(`
  custom_tags = {
    "foo" = "bar"
  }
`)
	} else if withTags && update {
		ret += fmt.Sprintf(`
  custom_tags = {
    "foo" = "bar"
    "baz" = "bux"
  }
`)
	}

	if update {
		ret += fmt.Sprintf(`
  granularity = "secret-key"
`)
	} else {
		ret += fmt.Sprintf(`
  granularity = "secret-path"
`)
	}
	return ret
}
