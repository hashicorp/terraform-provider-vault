// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
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

	// envAWSSecretsSyncOwnerTag is the environment variable used to inject an
	// "Owner" custom tag into the AWS secrets sync destination acceptance test
	// resources. When set, its value is applied as the value of the "Owner"
	// custom tag on every destination created by these tests, which is required
	// for permission issues encountered in doormat AWS account.
	// When unset, no "Owner" tag is added and test behavior is unchanged.
	envAWSSecretsSyncOwnerTag = "TEST_AWS_SECRETS_SYNC_OWNER_TAG"

	// awsSecretsSyncOwnerTagKey is the custom tag key used for the owner tag.
	awsSecretsSyncOwnerTagKey = "Owner"
)

// awsSyncCustomTagsWithOwner returns a copy of base with the "Owner" custom tag
// added when the envAWSSecretsSyncOwnerTag environment variable is set.
func awsSyncCustomTagsWithOwner(base map[string]string) map[string]string {
	tags := map[string]string{}
	for k, v := range base {
		tags[k] = v
	}
	if owner := os.Getenv(envAWSSecretsSyncOwnerTag); owner != "" {
		tags[awsSecretsSyncOwnerTagKey] = owner
	}
	return tags
}

// customTagsHCL renders a custom_tags block for the given tags. It returns an
// empty string when there are no tags so it can be safely embedded in configs.
func customTagsHCL(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}

	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("  custom_tags = {\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "    %q = %q\n", k, tags[k])
	}
	b.WriteString("  }\n")
	return b.String()
}

// testCheckCustomTags builds the resource checks for a custom_tags map,
// including the owner tag when the envAWSSecretsSyncOwnerTag env var is set.
func testCheckCustomTags(resourceName string, base map[string]string) resource.TestCheckFunc {
	tags := awsSyncCustomTagsWithOwner(base)
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "custom_tags.%", strconv.Itoa(len(tags))),
	}
	for k, v := range tags {
		checks = append(checks, resource.TestCheckResourceAttr(resourceName, "custom_tags."+k, v))
	}
	return resource.ComposeTestCheckFunc(checks...)
}

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
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "arn:aws:iam::123456789012:role/test-role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "external-id-test"),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar"}),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "arn:aws:iam::123456789012:role/updated-role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "external-id-updated"),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar", "baz": "bux"}),
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

func TestAWSSecretsSyncDestinationWithCustomEncryption(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-enc")

	resourceName := "vault_secrets_sync_aws_destination.test"

	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion210)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretsSyncDestinationConfigWithCustomEncryption(accessKey, secretKey, region, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKmsKeyID, "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar"}),
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

func TestAWSSecretsSyncDestinationWithReplication(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-rep")

	resourceName := "vault_secrets_sync_aws_destination.test"

	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion210)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretsSyncDestinationConfigWithReplication(accessKey, secretKey, region, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicaRegions+".%", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicaRegions+".us-east-2", "arn:aws:kms:us-east-2:123456789012:key/mrk-1234567890abcdef1234567890abcdef"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldReplicaRegions+".us-west-1", "arn:aws:kms:us-west-1:123456789012:key/mrk-1234567890abcdef1234567890abcdef"),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar"}),
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

// TestAWSSecretsSyncDestination_UnsupportedVersionFields verifies that configuring the
// Vault 2.1.0+ fields (kms_key_id, replica_regions) against a Vault server older than
// 2.1.0 fails with the intended validation error, rather than silently ignoring them or
// failing later. Guarded so it only runs on Vault < 2.1.0.
func TestAWSSecretsSyncDestination_UnsupportedVersionFields(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-ver")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionGTE(t, testProvider.Meta(), provider.VaultVersion210)
		},
		Steps: []resource.TestStep{
			{
				Config:      testAWSSecretsSyncDestinationConfig_kmsKeyID(destName),
				ExpectError: regexp.MustCompile(`kms_key_id is only supported in Vault Enterprise 2.1.0 and later`),
			},
			{
				Config:      testAWSSecretsSyncDestinationConfig_replicaRegions(destName),
				ExpectError: regexp.MustCompile(`replica_regions is only supported in Vault Enterprise 2.1.0 and later`),
			},
		},
	})
}

func testAWSSecretsSyncDestinationConfig_kmsKeyID(destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name       = "%s"
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}
`, destName)
}

func testAWSSecretsSyncDestinationConfig_replicaRegions(destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name   = "%s"
  region = "us-east-1"

  replica_regions = {
    "us-west-2" = "arn:aws:kms:us-west-2:123456789012:key/mrk-1234567890abcdef1234567890abcdef"
  }
}
`, destName)
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
%s
}
`, destName, accessKey, secretKey, region, customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
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
%s
}
`, destName, accessKey, secretKey, region, customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
}

func testAWSSecretsSyncDestinationConfig_initial(accessKey, secretKey, region, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                  = "%s"
  access_key_id	        = "%s"
  secret_access_key     = "%s"
  region                = "%s"
  role_arn              = "arn:aws:iam::123456789012:role/test-role"
  external_id           = "external-id-test"
  %s
}
`, destName, accessKey, secretKey, region, testSecretsSyncDestinationCommonConfig(templ, false, true, false))

	return ret
}

func testAWSSecretsSyncDestinationConfigWithCustomEncryption(accessKey, secretKey, region, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name              = "%s"
  access_key_id     = "%s"
  secret_access_key = "%s"
  region            = "%s"
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  %s
}
`, destName, accessKey, secretKey, region, testSecretsSyncDestinationCommonConfig(templ, true, true, false))

	return ret
}

func testAWSSecretsSyncDestinationConfigWithReplication(accessKey, secretKey, region, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name              = "%s"
  access_key_id     = "%s"
  secret_access_key = "%s"
  region            = "%s"
  replica_regions = {
    "us-east-2" = "arn:aws:kms:us-east-2:123456789012:key/mrk-1234567890abcdef1234567890abcdef",
    "us-west-1" = "arn:aws:kms:us-west-1:123456789012:key/mrk-1234567890abcdef1234567890abcdef"
  }
  %s
}
`, destName, accessKey, secretKey, region, testSecretsSyncDestinationCommonConfig(templ, true, true, false))

	return ret
}

func testAWSSecretsSyncDestinationConfig_updated(accessKey, secretKey, region, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                  = "%s"
  access_key_id         = "%s"
  secret_access_key     = "%s"
  region                = "%s"
  role_arn              = "arn:aws:iam::123456789012:role/updated-role"
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
%s
}
`, destName, accessKey, secretKey, region, customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
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
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion200)
			if !provider.IsEnterpriseSupported(testProvider.Meta()) {
				t.Skip("Skipping WIF test: requires Vault Enterprise")
			}
		},
		PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretsSyncDestinationWIFConfig(destName, region, audience, 30, roleArn, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, roleArn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWOVersion, "1"),
					// write-only fields must not be stored in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenKeyWO),
				),
			},
			{
				Config: testAWSSecretsSyncDestinationWIFConfig(destName, region, audience, 60, roleArn, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, roleArn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWOVersion, "2"),
					// write-only fields must not be stored in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenKeyWO),
				),
			},
			// Import before the error step so Vault state is not corrupted by the partial apply from the error step.
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessKeyID,
				fieldSecretAccessKey,
				consts.FieldIdentityTokenAudienceWO,
				consts.FieldIdentityTokenKeyWO,
				consts.FieldDisableStrictNetworking,
				consts.FieldIdentityTokenTTL,
				consts.FieldRoleArn,
			),
			{ // Missing role_arn when using WIF should error
				Config:      testAWSSecretsSyncDestinationWIFConfigMissingRoleArn(destName+"-no-role-arn", region, audience),
				ExpectError: regexp.MustCompile(`role_arn|invalid|error`),
			},
		},
	})
}

func testAWSSecretsSyncDestinationWIFConfig(destName, region, audience string, ttl int, roleArn string, identity_token_audience_wo_version int) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                               = "%s"
  region                             = "%s"
  role_arn                           = "%s"
  identity_token_audience_wo         = "%s"
  identity_token_audience_wo_version = %d
  identity_token_ttl                 = %d
  granularity                        = "secret-path"
%s
}`, destName, region, roleArn, audience, identity_token_audience_wo_version, ttl, customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
}

func testAWSSecretsSyncDestinationWIFConfigMissingRoleArn(destName, region, audience string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_destination" "test" {
  name                               = "%s"
  region                             = "%s"
  identity_token_audience_wo         = "%s"
  identity_token_audience_wo_version = 2
  identity_token_ttl                 = 30
  granularity                        = "secret-path"
}`, destName, region, audience)
}

func testSecretsSyncDestinationCommonConfig(templ string, withTemplate, withTags, update bool) string {
	ret := ""
	if withTemplate {
		ret += fmt.Sprintf(`
  secret_name_template = "%s"
`, templ)
	}

	if withTags {
		base := map[string]string{"foo": "bar"}
		if update {
			base["baz"] = "bux"
		}
		ret += customTagsHCL(awsSyncCustomTagsWithOwner(base))
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
