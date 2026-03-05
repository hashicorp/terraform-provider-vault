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

func TestAccAWSSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldUsernameTemplate),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
			{
				Config: testAccAWSSecretBackendConfig_updated(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "43200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-west-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMEndpoint, "https://iam.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, "https://sts.us-west-1.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_noCreds(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "43200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-west-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
				),
			},
		},
	})
}

func TestAccAWSSecretBackend_fallback(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_fallback(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, "https://sts.us-west-1.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSRegion, "us-west-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackRegions+".0", "us-east-2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackRegions+".1", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackRegions+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackEndpoints+".0", "https://sts.us-east-2.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackEndpoints+".1", "https://sts.us-east-1.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackEndpoints+".#", "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
			{
				Config: testAccAWSSecretBackendConfig_fallbackUpdated(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "updated description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, "https://sts.us-central-2.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSRegion, "us-central-2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackRegions+".0", "us-east-2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackRegions+".1", "eu-central-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackRegions+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackEndpoints+".0", "https://sts.us-east-2.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackEndpoints+".1", "https://sts.eu-central-1.amazonaws.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSFallbackEndpoints+".#", "2"),
				),
			},
		},
	})
}

func TestAccAWSSecretBackend_wif(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_wifBasic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "test-role-arn"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_wifUpdated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "test-role-arn-updated"),
				),
			},
		},
	})
}

// TestAccAWSSecretBackend_automatedRotation tests that Automated
// Root Rotation parameters are compatible with the AWS Secrets Backend
// resource
func TestAccAWSSecretBackend_automatedRotation(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_automatedRotation(path, "", 10, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// zero-out rotation_period
			{
				Config: testAccAWSSecretBackendConfig_automatedRotation(path, "*/20 * * * *", 0, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "120"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				Config:      testAccAWSSecretBackendConfig_automatedRotation(path, "", 30, 120, true),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			// zero-out rotation_schedule and rotation_window
			{
				Config: testAccAWSSecretBackendConfig_automatedRotation(path, "", 30, 0, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
		},
	})
}

func TestAccAWSSecretBackend_usernameTempl(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	templ := fmt.Sprintf(`{{ printf \"vault-%%s-%%s-%%s\" (printf \"%%s-%%s\" (.DisplayName) (.PolicyName) | truncate 42) (unix_time) (random 20) | truncate 64 }}`)
	expectedTempl := fmt.Sprintf(`{{ printf "vault-%%s-%%s-%%s" (printf "%%s-%%s" (.DisplayName) (.PolicyName) | truncate 42) (unix_time) (random 20) | truncate 64 }}`)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_userTemplate(path, accessKey, secretKey, templ),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameTemplate, expectedTempl),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
		},
	})
}

func TestAccAWSSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	updatedPath := acctest.RandomWithPrefix("tf-test-aws-updated")

	resourceName := "vault_aws_secret_backend.test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_basic(updatedPath, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
		},
	})
}

func TestAccAWSSecretBackendRole_MountConfig(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")

	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_MountConfig(path, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, "access-key-test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, "secret-key-test"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "36000"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.0", "header1"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.0", "header1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resourceName, "force_no_cache", "true"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_MountConfig(path, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, "access-key-test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, "secret-key-test"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "48000"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.0", "header1"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.0", "header1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.2", "header3"),
					resource.TestCheckResourceAttr(resourceName, "listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resourceName, "force_no_cache", "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldDisableRemount,
				consts.FieldSecretKey),
		},
	})
}

func TestAccAWSSecretBackend_max_retries(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_max_retry_basic(path, accessKey, secretKey, 3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "3"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_max_retry_updated(path, accessKey, secretKey, 5),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "2100"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "21070"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "5"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_no_max_retry(path, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test no max_retry description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSTSEndpoint, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "-1"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldUsernameTemplate),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_max_retry_basic(path, accessKey, secretKey, -1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "-1"),
				),
			},
			{
				Config: testAccAWSSecretBackendConfig_max_retry_basic(path, accessKey, secretKey, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "0"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
		},
	})
}

func TestAccAWSSecretBackend_secretKeyConflicts(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path                  = "%s"
  secret_key            = "test-secret-key"
  secret_key_wo         = "test-secret-key-wo"
  secret_key_wo_version = 1
}`, path),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
		},
	})
}

func testAccAWSSecretBackendConfig_MountConfig(path string, isUpdate bool) string {
	if !isUpdate {

		return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path 					      = "%s"
  description 			      = "test desc"
  access_key                  = "access-key-test"
  secret_key                  = "secret-key-test"
  default_lease_ttl_seconds   = 3600
  max_lease_ttl_seconds       = 36000
  passthrough_request_headers = ["header1", "header2"]
  allowed_response_headers    = ["header1", "header2"]
  delegated_auth_accessors    = ["header1", "header2"]
  listing_visibility          = "hidden"
  force_no_cache              = true
}`, path)
	} else {
		return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path 					      = "%s"
  description 			      = "test desc updated"
  access_key                  = "access-key-test"
  secret_key                  = "secret-key-test"
  default_lease_ttl_seconds   = 7200
  max_lease_ttl_seconds       = 48000
  passthrough_request_headers = ["header1", "header2"]
  allowed_response_headers    = ["header1", "header2", "header3"]
  delegated_auth_accessors    = ["header1", "header2"]
  listing_visibility          = "unauth"
  force_no_cache              = true
}`, path)
	}
}

func testAccAWSSecretBackendConfig_basic(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  access_key = "%s"
  secret_key = "%s"
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_updated(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description updated"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  access_key = "%s"
  secret_key = "%s"
  region = "us-west-1"

  iam_endpoint = "https://iam.amazonaws.com"
  sts_endpoint = "https://sts.us-west-1.amazonaws.com"
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_fallback(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  access_key = "%s"
  secret_key = "%s"
  region = "us-west-1"

  iam_endpoint = "https://iam.amazonaws.com"
  sts_endpoint = "https://sts.us-west-1.amazonaws.com"

  sts_region = "us-west-1"
  sts_fallback_regions = ["us-east-2", "us-east-1"]
  sts_fallback_endpoints = ["https://sts.us-east-2.amazonaws.com","https://sts.us-east-1.amazonaws.com"]
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_fallbackUpdated(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "updated description"
  default_lease_ttl_seconds = 60
  max_lease_ttl_seconds = 1000
  access_key = "%s"
  secret_key = "%s"
  region = "us-central-2"

  sts_endpoint = "https://sts.us-central-2.amazonaws.com"

  sts_region = "us-central-2"
  sts_fallback_regions = ["us-east-2", "eu-central-1"]
  sts_fallback_endpoints = ["https://sts.us-east-2.amazonaws.com","https://sts.eu-central-1.amazonaws.com"]
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_wifBasic(path string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  identity_token_audience = "wif-audience"
  identity_token_ttl = 600
  role_arn = "test-role-arn"
}`, path)
}

func testAccAWSSecretBackendConfig_wifUpdated(path string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  identity_token_audience = "wif-audience-updated"
  identity_token_ttl = 1800
  role_arn = "test-role-arn-updated"
}`, path)
}

func testAccAWSSecretBackendConfig_noCreds(path string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  region = "us-west-1"
}`, path)
}

func testAccAWSSecretBackendConfig_userTemplate(path, accessKey, secretKey, templ string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  access_key = "%s"
  secret_key = "%s"
  username_template = "%s"
}`, path, accessKey, secretKey, templ)
}

func testAccAWSSecretBackendConfig_automatedRotation(path, schedule string, period, window int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  rotation_period = "%d"
  rotation_schedule = "%s"
  rotation_window = "%d"
  disable_automated_rotation = %t
}`, path, period, schedule, window, disable)
}

func testAccAWSSecretBackendConfig_no_max_retry(path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test no max_retry description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  access_key = "%s"
  secret_key = "%s"
}`, path, accessKey, secretKey)
}

func testAccAWSSecretBackendConfig_max_retry_basic(path, accessKey, secretKey string, maxRetry int) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  access_key = "%s"
  secret_key = "%s"
  max_retries = "%d"
}`, path, accessKey, secretKey, maxRetry)
}

func testAccAWSSecretBackendConfig_max_retry_updated(path, accessKey, secretKey string, maxRetry int) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description updated"
  default_lease_ttl_seconds = 2100
  max_lease_ttl_seconds = 21070
  access_key = "%s"
  secret_key = "%s"
  max_retries = "%d"
}`, path, accessKey, secretKey, maxRetry)
}

func TestAccAWSSecretBackend_secretKeyWriteOnly(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_secret_backend"
	resourceName := resourceType + ".test"
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendConfig_secretKeyWO(path, accessKey, secretKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					// secret_key_wo is write-only, so it should not be in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
				),
			},
			// Update secret_key_wo by incrementing the version
			{
				Config: testAccAWSSecretBackendConfig_secretKeyWO(path, accessKey, secretKey+"-updated", 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, accessKey),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldSecretKey,
				consts.FieldSecretKeyWO,
				consts.FieldSecretKeyWOVersion,
				consts.FieldDisableRemount),
		},
	})
}

func testAccAWSSecretBackendConfig_secretKeyWO(path, accessKey, secretKey string, version int) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  access_key = "%s"
  secret_key_wo = "%s"
  secret_key_wo_version = %d
}`, path, accessKey, secretKey, version)
}
