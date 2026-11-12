// Copyright IBM Corp. 2016, 2026
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
	defaultAwsAcmCertificateNameTemplate = "vault/{{ .MountAccessor }}/{{ .CommonName }}"
	updatedAwsAcmCertificateNameTemplate = "vault-{{ .MountAccessor }}-{{ .CommonName }}"
)

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

	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSACMSecretsSyncDestinationConfig_initial(accessKey, secretKey, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsAcmSyncType),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeliveryMode, awsAcmDeliveryModeFullBundle),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCertificateNameTemplate, defaultAwsAcmCertificateNameTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "arn:aws:iam::123456789012:role/test-role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "external-id-test"),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar"}),
				),
			},
			{
				Config: testAWSACMSecretsSyncDestinationConfig_updated(accessKey, secretKey, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsAcmSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeliveryMode, awsAcmDeliveryModeFullBundle),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCertificateNameTemplate, updatedAwsAcmCertificateNameTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "arn:aws:iam::123456789012:role/updated-role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, "external-id-updated"),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar", "baz": "bux"}),
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv4_addresses.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "allowed_ipv4_addresses.*", "10.0.0.0/8"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ports.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "allowed_ports.*", "443"),
				),
			},
			{
				// Vault replaces the full tag set on update, so removed tags must not come back.
				Config: testAWSACMSecretsSyncDestinationConfig_tagsRemoved(accessKey, secretKey, region, destName),
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

func testAWSACMSecretsSyncDestinationConfig_initial(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name              = "%s"
  access_key_id     = "%s"
  secret_access_key = "%s"
  region            = "%s"
  role_arn          = "arn:aws:iam::123456789012:role/test-role"
  external_id       = "external-id-test"
  delivery_mode     = "full_bundle"
%s
}
`, destName, accessKey, secretKey, region, customTagsHCL(awsSyncCustomTagsWithOwner(map[string]string{"foo": "bar"})))
}

func testAWSACMSecretsSyncDestinationConfig_updated(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                      = "%s"
  access_key_id             = "%s"
  secret_access_key         = "%s"
  region                    = "%s"
  role_arn                  = "arn:aws:iam::123456789012:role/updated-role"
  external_id               = "external-id-updated"
  delivery_mode             = "full_bundle"
  certificate_name_template = "%s"
  allowed_ipv4_addresses    = ["10.0.0.0/8"]
  allowed_ports             = [443]
%s
}
`, destName, accessKey, secretKey, region, updatedAwsAcmCertificateNameTemplate,
		customTagsHCL(awsSyncCustomTagsWithOwner(map[string]string{"foo": "bar", "baz": "bux"})))
}

func testAWSACMSecretsSyncDestinationConfig_tagsRemoved(accessKey, secretKey, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                      = "%s"
  access_key_id             = "%s"
  secret_access_key         = "%s"
  region                    = "%s"
  role_arn                  = "arn:aws:iam::123456789012:role/updated-role"
  external_id               = "external-id-updated"
  delivery_mode             = "full_bundle"
  certificate_name_template = "%s"
  allowed_ipv4_addresses    = ["10.0.0.0/8"]
  allowed_ports             = [443]
%s
}
`, destName, accessKey, secretKey, region, updatedAwsAcmCertificateNameTemplate,
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
