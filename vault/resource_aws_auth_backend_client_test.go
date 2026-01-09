// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAWSAuthBackendClient_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_basic(backend),
				Check:  testAccAWSAuthBackendClientCheck_attrs(backend),
			},
			{
				ResourceName:            "vault_aws_auth_backend_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"secret_key"},
			},
		},
	})
}

func TestAccAWSAuthBackendClient_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_basic(backend),
				Check:  testAccAWSAuthBackendClientCheck_attrs(backend),
			},
			{
				Config: testAccAWSAuthBackendClientConfig_updated(backend),
				Check:  testAccAWSAuthBackendClientCheck_attrs(backend),
			},
		},
	})
}

func TestAccAWSAuthBackendClient_nested(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws") + "/nested"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_basic(backend),
				Check:  testAccAWSAuthBackendClientCheck_attrs(backend),
			},
			{
				Config: testAccAWSAuthBackendClientConfig_updated(backend),
				Check:  testAccAWSAuthBackendClientCheck_attrs(backend),
			},
		},
	})
}

func TestAccAWSAuthBackendClient_withoutSecretKey(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_basicWithoutSecretKey(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendClientCheck_attrs(backend),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_client.client", consts.FieldAccessKey, "AWSACCESSKEY"),
					resource.TestCheckNoResourceAttr("vault_aws_auth_backend_client.client", consts.FieldSecretKey),
				),
			},
			{
				Config: testAccAWSAuthBackendClientConfig_updatedWithoutSecretKey(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendClientCheck_attrs(backend),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_client.client", consts.FieldAccessKey, "AWSACCESSKEY"),
					resource.TestCheckNoResourceAttr("vault_aws_auth_backend_client.client", consts.FieldSecretKey),
				),
			},
		},
	})
}

func TestAccAWSAuthBackend_wif(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_client.client"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		CheckDestroy: testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClient_wifBasic(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "test-role-arn"),
				),
			},
			{
				Config: testAccAWSAuthBackendClient_wifUpdated(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, "test-role-arn-updated"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestAccAWSAuthBackendClientStsRegionNoEndpoint(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccAWSAuthBackendClientConfigSTSRegionNoEndpoint(backend),
				ExpectError: regexp.MustCompile("Error: both sts_endpoint and sts_region need to be set"),
			},
		},
	})
}

func TestAccAWSAuthBackendClientStsRegionFromClient(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfigSTSRegionFromClient(backend, false),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendClientCheck_attrs(backend),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_client.client", useSTSRegionFromClient, "false"),
				),
			},
			{
				Config: testAccAWSAuthBackendClientConfigSTSRegionFromClient(backend, true),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendClientCheck_attrs(backend),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_client.client", useSTSRegionFromClient, "true"),
				),
			},
			testutil.GetImportTestStep("vault_aws_auth_backend_client.client", false, nil),
		},
	})
}

// TestAccAWSAuthBackendClient_automatedRotation tests that Automated
// Root Rotation parameters are compatible with the AWS Auth Backend Client
// resource
func TestAccAWSAuthBackendClient_automatedRotation(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_auth_backend_client"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAWS, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfigAutomatedRootRotation(path, "", 10, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// zero-out rotation_period
			{
				Config: testAccAWSAuthBackendClientConfigAutomatedRootRotation(path, "*/20 * * * *", 0, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "120"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				Config:      testAccAWSAuthBackendClientConfigAutomatedRootRotation(path, "", 30, 120, true),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			// zero-out rotation_schedule and rotation_window
			{
				Config: testAccAWSAuthBackendClientConfigAutomatedRootRotation(path, "", 30, 0, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
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

// TestAccAWSAuthBackendClient_SecretKeyWriteOnly tests the write-only secret_key field
func TestAccAWSAuthBackendClient_SecretKeyWriteOnly(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_client.client"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			// Step 1: Create with write-only secret (version 1)
			{
				Config: testAccAWSAuthBackendClientConfig_secretKeyWriteOnly(backend, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, "AWSACCESSKEY"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "1"),
					// Write-only field should NOT be in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					// Legacy field should NOT be set
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKey),
				),
			},
			// Step 2: Rotate secret (version 1 -> 2)
			{
				Config: testAccAWSAuthBackendClientConfig_secretKeyWriteOnly(backend, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, "AWSACCESSKEY"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKey),
				),
			},
			// Step 3: Update other fields without changing secret (version stays at 2)
			{
				Config: testAccAWSAuthBackendClientConfig_secretKeyWriteOnlyWithUpdatedEndpoint(backend, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, "AWSACCESSKEY"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKeyWOVersion, "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEC2Endpoint, "http://updated.vault.test/ec2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKey),
				),
			},
		},
	})
}

// TestAccAWSAuthBackendClient_SecretKeyLegacy tests backward compatibility with legacy secret_key field
func TestAccAWSAuthBackendClient_SecretKeyLegacy(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_client.client"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			// Create with legacy secret_key field
			{
				Config: testAccAWSAuthBackendClientConfig_secretKeyLegacy(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, "AWSACCESSKEY"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, "LEGACYSECRETKEY"),
					// Write-only fields should NOT be set
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWOVersion),
				),
			},
			// Update with legacy field
			{
				Config: testAccAWSAuthBackendClientConfig_secretKeyLegacyUpdated(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAccessKey, "UPDATEDACCESSKEY"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretKey, "UPDATEDSECRETKEY"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldSecretKeyWOVersion),
				),
			},
		},
	})
}

// TestAccAWSAuthBackendClient_SecretKeyWriteOnlyConflicts tests negative scenarios
func TestAccAWSAuthBackendClient_SecretKeyWriteOnlyConflicts(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Negative Test 1: secret_key and secret_key_wo cannot be used together
			{
				Config:      testAccAWSAuthBackendClientConfig_secretKeyConflict(backend, 1),
				ExpectError: regexp.MustCompile(`.*conflicts with.*`),
			},
			// Negative Test 2: secret_key_wo_version requires secret_key_wo
			{
				Config:      testAccAWSAuthBackendClientConfig_versionWithoutSecretKeyWO(backend),
				ExpectError: regexp.MustCompile(`all of .+secret_key_wo.+secret_key_wo_version.+ must\s+be\s+specified`),
			},
		},
	})
}

func testAccCheckAWSAuthBackendClientDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_client" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AWS auth backend %q client config: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AWS auth backend %q still configured", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAWSAuthBackendClientCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_aws_auth_backend_client.client"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/"+backend+"/config/client" {
			return fmt.Errorf("expected ID to be %q, got %q", "auth/"+backend+"/config/client", endpoint)
		}

		client, e := provider.GetClient(instanceState, testProvider.Meta())
		if e != nil {
			return e
		}

		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back AWS auth client config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("AWS auth client not configured at %q", endpoint)
		}
		attrs := map[string]string{
			consts.FieldAccessKey:              consts.FieldAccessKey,
			consts.FieldEC2Endpoint:            "endpoint",
			consts.FieldIAMEndpoint:            consts.FieldIAMEndpoint,
			consts.FieldSTSEndpoint:            consts.FieldSTSEndpoint,
			consts.FieldSTSRegion:              consts.FieldSTSRegion,
			consts.FieldIAMServerIDHeaderValue: consts.FieldIAMServerIDHeaderValue,
			consts.FieldMaxRetries:             consts.FieldMaxRetries,
		}
		for stateAttr, apiAttr := range attrs {
			respApiAttr := resp.Data[apiAttr]
			if respApiAttr == nil {
				return fmt.Errorf("expected non-nil value for %s (%s) of %q", apiAttr, stateAttr, endpoint)
			}
			if respApiAttr != nil {
				if apiAttr == consts.FieldMaxRetries {
					respApiAttr = respApiAttr.(json.Number).String()
				}
				if respApiAttr != instanceState.Attributes[stateAttr] {
					return fmt.Errorf("expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], respApiAttr)
				}
			}
		}
		return nil
	}
}

func testAccAWSAuthBackendClient_wifBasic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  identity_token_audience = "wif-audience"
  identity_token_ttl = 600
  role_arn = "test-role-arn"
}
`, backend)
}

func testAccAWSAuthBackendClient_wifUpdated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  identity_token_audience = "wif-audience-updated"
  identity_token_ttl = 1800
  role_arn = "test-role-arn-updated"
}
`, backend)
}

func testAccAWSAuthBackendClientConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  secret_key = "AWSSECRETKEY"
  ec2_endpoint = "http://vault.test/ec2"
  iam_endpoint = "http://vault.test/iam"
  sts_endpoint = "http://vault.test/sts"
  sts_region = "vault-test"
  iam_server_id_header_value = "vault.test"
  max_retries = "-1"
}
`, backend)
}

func testAccAWSAuthBackendClientConfig_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "UPDATEDAWSACCESSKEY"
  secret_key = "UPDATEDAWSSECRETKEY"
  ec2_endpoint = "http://updated.vault.test/ec2"
  iam_endpoint = "http://updated.vault.test/iam"
  sts_endpoint = "http://updated.vault.test/sts"
  sts_region = "updated-vault-test"
  iam_server_id_header_value = "updated.vault.test"
  max_retries = "0"
}`, backend)
}

func testAccAWSAuthBackendClientConfig_basicWithoutSecretKey(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  ec2_endpoint = "http://vault.test/ec2"
  iam_endpoint = "http://vault.test/iam"
  sts_endpoint = "http://vault.test/sts"
  sts_region = "vault-test"
  iam_server_id_header_value = "vault.test"
}`, backend)
}

func testAccAWSAuthBackendClientConfig_updatedWithoutSecretKey(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  ec2_endpoint = "http://updated2.vault.test/ec2"
  iam_endpoint = "http://updated2.vault.test/iam"
  sts_endpoint = "http://updated2.vault.test/sts"
  sts_region = "updated-vault-test"
  iam_server_id_header_value = "updated2.vault.test"
}`, backend)
}

func testAccAWSAuthBackendClientConfigSTSRegionNoEndpoint(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  ec2_endpoint = "http://vault.test/ec2"
  iam_endpoint = "http://vault.test/iam"
  sts_region = "vault-test"
  iam_server_id_header_value = "vault.test"
}`, backend)
}

func testAccAWSAuthBackendClientConfigSTSRegionFromClient(backend string, useSTSRegionFromClient bool) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  use_sts_region_from_client = %v
}`, backend, useSTSRegionFromClient)
}

func testAccAWSAuthBackendClientConfigAutomatedRootRotation(backend, schedule string, period, window int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "test" {
  backend = vault_auth_backend.test.path
  rotation_period = "%d"
  rotation_schedule = "%s"
  rotation_window = "%d"
  disable_automated_rotation = %t
}`, backend, period, schedule, window, disable)
}

func testAccAWSAuthBackendClientCheck_allowedSTSHeaderValues(backend string, expectedHeaders []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_aws_auth_backend_client.client"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := instanceState.ID
		client, e := provider.GetClient(instanceState, testProvider.Meta())
		if e != nil {
			return e
		}

		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back AWS auth client config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("AWS auth client not configured at %q", endpoint)
		}

		// Check allowed_sts_header_values field - Vault returns this as []interface{}
		if headersInterface, ok := resp.Data[consts.FieldAllowedSTSHeaderValues]; ok {
			if headersList, ok := headersInterface.([]interface{}); ok {
				if len(expectedHeaders) == 0 {
					if len(headersList) != 0 {
						return fmt.Errorf("expected empty allowed_sts_header_values, got %d headers: %v", len(headersList), headersList)
					}
				} else {
					actualHeaders := make([]string, len(headersList))
					for i, header := range headersList {
						if headerStr, ok := header.(string); ok {
							actualHeaders[i] = headerStr
						} else {
							return fmt.Errorf("header at index %d is not a string: %v", i, header)
						}
					}

					// Check that all expected headers are present (allowing for duplicates)
					for _, expected := range expectedHeaders {
						found := false
						for _, actual := range actualHeaders {
							if actual == expected {
								found = true
								break
							}
						}
						if !found {
							return fmt.Errorf("expected header %q not found in %v", expected, actualHeaders)
						}
					}

					// Also verify that we don't have unexpected headers (deduplicate first)
					uniqueActual := make(map[string]bool)
					for _, header := range actualHeaders {
						uniqueActual[header] = true
					}
					expectedSet := make(map[string]bool)
					for _, header := range expectedHeaders {
						expectedSet[header] = true
					}
					for actual := range uniqueActual {
						if !expectedSet[actual] {
							return fmt.Errorf("unexpected header %q found in response", actual)
						}
					}
				}
			} else {
				return fmt.Errorf("allowed_sts_header_values is not a slice: %T", headersInterface)
			}
		} else if len(expectedHeaders) > 0 {
			return fmt.Errorf("expected allowed_sts_header_values to be set, but was nil")
		}

		return nil
	}
}

func TestAccAWSAuthBackendClient_allowedSTSHeaderValues(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_client.client"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_basic(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "X-Custom-Header"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "X-Another-Header"),
					// Additional validation directly from Vault API
					testAccAWSAuthBackendClientCheck_allowedSTSHeaderValues(backend, []string{"X-Custom-Header", "X-Another-Header"}),
				),
			},
			{
				Config: testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_updated(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "X-Updated-Header"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "X-New-Header"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "X-Third-Header"),
					// Additional validation directly from Vault API
					testAccAWSAuthBackendClientCheck_allowedSTSHeaderValues(backend, []string{"X-Updated-Header", "X-New-Header", "X-Third-Header"}),
				),
			},
			{
				Config: testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_empty(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".#", "0"),
					// Additional validation directly from Vault API for empty case
					testAccAWSAuthBackendClientCheck_allowedSTSHeaderValues(backend, []string{}),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey),
		},
	})
}

func TestAccAWSAuthBackendClient_allowedSTSHeaderValues_canonicalization(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_client.client"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_canonicalization(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".#", "3"),
					// All variations should be canonicalized to proper HTTP header format
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "X-Custom-Header"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "Content-Type"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "Authorization"),
					// Additional validation directly from Vault API - verify canonicalization worked
					testAccAWSAuthBackendClientCheck_allowedSTSHeaderValues(backend, []string{"X-Custom-Header", "Content-Type", "Authorization"}),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey),
		},
	})
}

func TestAccAWSAuthBackendClient_allowedSTSHeaderValues_duplicateHandling(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_client.client"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_duplicateHandling(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					// Should only have 2 unique headers after deduplication
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".#", "2"),
					// Both should be canonicalized and deduplicated
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "Content-Type"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAllowedSTSHeaderValues+".*", "Authorization"),
					// Validate that duplicates were properly handled in Vault
					testAccAWSAuthBackendClientCheck_allowedSTSHeaderValues(backend, []string{"Content-Type", "Authorization"}),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey),
		},
	})
}

func testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  secret_key = "AWSSECRETKEY"
  allowed_sts_header_values = [
    "x-custom-header",
    "x-another-header"
  ]
}
`, backend)
}

func testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  secret_key = "AWSSECRETKEY"
  allowed_sts_header_values = [
    "x-updated-header",
    "x-new-header",
    "x-third-header"
  ]
}
`, backend)
}

func testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_empty(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  secret_key = "AWSSECRETKEY"
  allowed_sts_header_values = []
}
`, backend)
}

func testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_canonicalization(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  secret_key = "AWSSECRETKEY"
  allowed_sts_header_values = [
    "x-custom-header",    # Should be canonicalized to X-Custom-Header
    "CONTENT-TYPE",       # Should be canonicalized to Content-Type
    "authorization"       # Should be canonicalized to Authorization
  ]
}
`, backend)
}

func testAccAWSAuthBackendClientConfig_allowedSTSHeaderValues_duplicateHandling(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for duplicate header handling"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = vault_auth_backend.aws.path
  access_key = "AWSACCESSKEY"
  secret_key = "AWSSECRETKEY" 
  allowed_sts_header_values = [
    "content-type",       # Should be canonicalized to Content-Type
    "Content-Type",       # Already canonical - should be deduplicated
    "CONTENT-TYPE",       # Should be canonicalized to Content-Type - duplicate
    "authorization",      # Should be canonicalized to Authorization
    "Authorization",      # Already canonical - should be deduplicated
    "AUTHORIZATION"       # Should be canonicalized to Authorization - duplicate
  ]
}
`, backend)
}

func testAccAWSAuthBackendClientConfig_secretKeyWriteOnly(backend string, version int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for AWS client with write-only secret"
}

resource "vault_aws_auth_backend_client" "client" {
  backend                = vault_auth_backend.aws.path
  access_key             = "AWSACCESSKEY"
  secret_key_wo          = "super-secret-key-v%d"
  secret_key_wo_version  = %d
}
`, backend, version, version)
}

func testAccAWSAuthBackendClientConfig_secretKeyWriteOnlyWithUpdatedEndpoint(backend string, version int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for AWS client with write-only secret"
}

resource "vault_aws_auth_backend_client" "client" {
  backend                = vault_auth_backend.aws.path
  access_key             = "AWSACCESSKEY"
  secret_key_wo          = "super-secret-key-v%d"
  secret_key_wo_version  = %d
  ec2_endpoint           = "http://updated.vault.test/ec2"
}
`, backend, version, version)
}

func testAccAWSAuthBackendClientConfig_secretKeyLegacy(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for AWS client with legacy secret"
}

resource "vault_aws_auth_backend_client" "client" {
  backend     = vault_auth_backend.aws.path
  access_key  = "AWSACCESSKEY"
  secret_key  = "LEGACYSECRETKEY"
}
`, backend)
}

func testAccAWSAuthBackendClientConfig_secretKeyLegacyUpdated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for AWS client with legacy secret"
}

resource "vault_aws_auth_backend_client" "client" {
  backend     = vault_auth_backend.aws.path
  access_key  = "UPDATEDACCESSKEY"
  secret_key  = "UPDATEDSECRETKEY"
}
`, backend)
}

// Negative test configs
func testAccAWSAuthBackendClientConfig_secretKeyConflict(backend string, version int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for conflict testing"
}

resource "vault_aws_auth_backend_client" "client" {
  backend               = vault_auth_backend.aws.path
  access_key            = "AWSACCESSKEY"
  secret_key            = "LEGACYSECRETKEY"
  secret_key_wo         = "WRITEONLY-SECRET-KEY"
  secret_key_wo_version = %d
}
`, backend, version)
}

func testAccAWSAuthBackendClientConfig_versionWithoutSecretKeyWO(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for version without write-only field"
}

resource "vault_aws_auth_backend_client" "client" {
  backend               = vault_auth_backend.aws.path
  access_key            = "AWSACCESSKEY"
  secret_key            = "LEGACYSECRETKEY"
  secret_key_wo_version = 1
}
`, backend)
}
