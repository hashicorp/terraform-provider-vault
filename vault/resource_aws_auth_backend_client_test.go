// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAWSAuthBackendClient_import(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("aws") + "/nested"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_client.client"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("aws")
	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
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
	var p *schema.Provider
	path := acctest.RandomWithPrefix("tf-test-aws")
	resourceType := "vault_aws_auth_backend_client"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
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
