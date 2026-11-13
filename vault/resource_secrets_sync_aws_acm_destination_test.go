// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
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
	defaultAwsAcmCertificateNameTemplate = "vault/{{ .MountAccessor }}/{{ .CommonName }}"
	updatedAwsAcmCertificateNameTemplate = "vault-{{ .MountAccessor }}-{{ .CommonName }}"

	// envAWSACMVaultEnvCreds makes the ACM tests omit access_key_id and
	// secret_access_key, so that Vault uses the AWS credentials from its own
	// environment. Use it with temporary credentials: the aws-acm destination
	// does not accept a session token.
	envAWSACMVaultEnvCreds = "TEST_AWS_ACM_USE_VAULT_ENV_CREDS"
	envAWSACMRoleARN       = "TEST_AWS_ACM_ROLE_ARN"
	envAWSACMExternalID    = "TEST_AWS_ACM_EXTERNAL_ID"
)

type awsACMTestCreds struct {
	accessKey string
	secretKey string
}

func getTestAWSACMCreds(t *testing.T) awsACMTestCreds {
	t.Helper()
	if os.Getenv(envAWSACMVaultEnvCreds) != "" {
		return awsACMTestCreds{}
	}
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	return awsACMTestCreds{accessKey: accessKey, secretKey: secretKey}
}

func (c awsACMTestCreds) hcl() string {
	if c.accessKey == "" {
		return ""
	}
	return fmt.Sprintf("  access_key_id     = %q\n  secret_access_key = %q\n", c.accessKey, c.secretKey)
}

func (c awsACMTestCreds) check(resourceName string) resource.TestCheckFunc {
	if c.accessKey == "" {
		return resource.ComposeTestCheckFunc(
			resource.TestCheckNoResourceAttr(resourceName, fieldAccessKeyID),
			resource.TestCheckNoResourceAttr(resourceName, fieldSecretAccessKey),
		)
	}
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, c.accessKey),
		resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, c.secretKey),
	)
}

func TestAWSACMSecretsSyncDestination_schema(t *testing.T) {
	r := awsAcmSecretsSyncDestinationResource()
	if err := r.InternalValidate(nil, true); err != nil {
		t.Fatalf("schema failed internal validation: %s", err)
	}

	for _, field := range []string{consts.FieldGranularity, consts.FieldSecretNameTemplate, consts.FieldKmsKeyID, consts.FieldReplicaRegions} {
		if _, ok := r.Schema[field]; ok {
			t.Errorf("field %q is not supported by aws-acm destinations and must not be in the schema", field)
		}
	}

	for _, field := range []string{consts.FieldName, consts.FieldRegion} {
		if !r.Schema[field].ForceNew {
			t.Errorf("field %q must be ForceNew", field)
		}
	}

	deliveryMode := r.Schema[consts.FieldDeliveryMode]
	if !deliveryMode.Required {
		t.Errorf("field %q must be required", consts.FieldDeliveryMode)
	}

	tests := map[string]bool{
		"full_bundle": false,
		"cert_only":   true,
		"FULL_BUNDLE": true,
		"":            true,
	}
	for value, wantErr := range tests {
		_, errs := deliveryMode.ValidateFunc(value, consts.FieldDeliveryMode)
		if gotErr := len(errs) > 0; gotErr != wantErr {
			t.Errorf("delivery_mode %q: expected error=%t, got errors=%v", value, wantErr, errs)
		}
	}
}

func TestAWSACMSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-acm")
	resourceName := "vault_secrets_sync_aws_acm_destination.test"
	creds := getTestAWSACMCreds(t)
	region := testutil.GetTestAWSRegion(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSACMSecretsSyncDestinationConfig_initial(creds, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsAcmSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeliveryMode, awsAcmDeliveryModeFullBundle),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCertificateNameTemplate, defaultAwsAcmCertificateNameTemplate),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar"}),
					creds.check(resourceName),
				),
			},
			{
				Config: testAWSACMSecretsSyncDestinationConfig_updated(creds, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsAcmSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeliveryMode, awsAcmDeliveryModeFullBundle),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCertificateNameTemplate, updatedAwsAcmCertificateNameTemplate),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar", "baz": "bux"}),
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv4_addresses.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "allowed_ipv4_addresses.*", "0.0.0.0/0"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ports.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "allowed_ports.*", "443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "true"),
					creds.check(resourceName),
				),
			},
			{
				// Vault replaces the full tag set on update, so removed tags must not come back.
				Config: testAWSACMSecretsSyncDestinationConfig_tagsRemoved(creds, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldCertificateNameTemplate, updatedAwsAcmCertificateNameTemplate),
					testCheckCustomTags(resourceName, nil),
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

// TestAWSACMSecretsSyncDestination_assumeRole needs a real IAM role, because Vault
// validates the effective AWS identity through STS when an ACM destination is written.
func TestAWSACMSecretsSyncDestination_assumeRole(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-acm-role")
	resourceName := "vault_secrets_sync_aws_acm_destination.test"
	creds := getTestAWSACMCreds(t)
	region := testutil.GetTestAWSRegion(t)
	roleArn := testutil.SkipTestEnvUnset(t, envAWSACMRoleARN)[0]
	externalID := os.Getenv(envAWSACMExternalID)

	externalIDHCL := ""
	if externalID != "" {
		externalIDHCL = fmt.Sprintf("  external_id = %q\n", externalID)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name          = "%s"
  region        = "%s"
  delivery_mode = "full_bundle"
  role_arn      = "%s"
%s%s%s
}`, destName, region, roleArn, externalIDHCL, creds.hcl(), customTagsHCL(awsSyncCustomTagsWithOwner(nil))),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, roleArn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, externalID),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessKeyID,
				fieldSecretAccessKey,
				consts.FieldDisableStrictNetworking,
			),
		},
	})
}

func TestAWSACMSecretsSyncDestination_invalidDeliveryMode(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-acm")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name          = "%s"
  region        = "us-east-1"
  delivery_mode = "cert_only"
}`, destName),
				ExpectError: regexp.MustCompile(`expected delivery_mode to be one of \["full_bundle"\]`),
			},
		},
	})
}

func TestAWSACMSecretsSyncDestinationWIF(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-acm-wif")
	resourceName := "vault_secrets_sync_aws_acm_destination.test"
	region := testutil.GetTestAWSRegion(t)
	values := testutil.SkipTestEnvUnset(t, "IDENTITY_TOKEN_AUDIENCE", "ROLE_ARN")
	audience := values[0]
	roleArn := values[1]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSACMSecretsSyncDestinationWIFConfig(destName, region, audience, roleArn, 30, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, roleArn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeliveryMode, awsAcmDeliveryModeFullBundle),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenKeyWO),
				),
			},
			{
				Config: testAWSACMSecretsSyncDestinationWIFConfig(destName, region, audience, roleArn, 60, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWO),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldIdentityTokenAudienceWO,
				consts.FieldIdentityTokenAudienceWOVersion,
				consts.FieldIdentityTokenKeyWO,
				consts.FieldIdentityTokenKeyWOVersion,
				consts.FieldDisableStrictNetworking,
			),
			{
				Config: fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "conflict" {
  name                       = "%s-conflict"
  region                     = "%s"
  delivery_mode              = "full_bundle"
  access_key_id              = "AKIAEXAMPLE"
  identity_token_audience_wo = "%s"
}`, destName, region, audience),
				ExpectError: regexp.MustCompile(`conflicts with`),
			},
		},
	})
}

func testAWSACMSecretsSyncDestinationConfig_initial(creds awsACMTestCreds, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name          = "%s"
  region        = "%s"
  delivery_mode = "full_bundle"
%s%s
}
`, destName, region, creds.hcl(), customTagsHCL(awsSyncCustomTagsWithOwner(map[string]string{"foo": "bar"})))
}

// The networking step must still let Vault reach AWS STS, which it calls on every
// write of an ACM destination, so it allows all IPv4 addresses on port 443.
func testAWSACMSecretsSyncDestinationConfig_updated(creds awsACMTestCreds, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                      = "%s"
  region                    = "%s"
  delivery_mode             = "full_bundle"
  certificate_name_template = "%s"
  allowed_ipv4_addresses    = ["0.0.0.0/0"]
  allowed_ports             = [443]
  disable_strict_networking = true
%s%s
}
`, destName, region, updatedAwsAcmCertificateNameTemplate, creds.hcl(),
		customTagsHCL(awsSyncCustomTagsWithOwner(map[string]string{"foo": "bar", "baz": "bux"})))
}

func testAWSACMSecretsSyncDestinationConfig_tagsRemoved(creds awsACMTestCreds, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                      = "%s"
  region                    = "%s"
  delivery_mode             = "full_bundle"
  certificate_name_template = "%s"
  allowed_ipv4_addresses    = ["0.0.0.0/0"]
  allowed_ports             = [443]
  disable_strict_networking = true
%s%s
}
`, destName, region, updatedAwsAcmCertificateNameTemplate, creds.hcl(),
		customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
}

func testAWSACMSecretsSyncDestinationWIFConfig(destName, region, audience, roleArn string, ttl, audienceVersion int) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                               = "%s"
  region                             = "%s"
  role_arn                           = "%s"
  delivery_mode                      = "full_bundle"
  identity_token_audience_wo         = "%s"
  identity_token_audience_wo_version = %d
  identity_token_ttl                 = %d
%s
}`, destName, region, roleArn, audience, audienceVersion, ttl, customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
}
