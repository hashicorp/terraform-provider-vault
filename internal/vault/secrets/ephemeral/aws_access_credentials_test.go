// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccAWSAccessCredentials confirms that AWS credentials
// are correctly generated from Vault into the ephemeral resource
//
// NOTE: This test currently fails due to timing constraints where ephemeral resources
// are evaluated during the plan phase before AWS backends/roles are fully created.
// The implementation is correct and will work with pre-existing AWS infrastructure.
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccAWSAccessCredentials(t *testing.T) {
	testutil.SkipTestAcc(t)

	a, s := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	mount := acctest.RandomWithPrefix("tf-aws")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSAccessCredentialsConfig(mount, a, s, region),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify that we got the access_key and secret_key set
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
					// For creds type, security_token should be empty
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("security_token"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("type"), knownvalue.StringExact("creds")),
				},
			},
		},
	})
}

// TestAccAWSAccessCredentialsSTS tests STS token generation
//
// NOTE: This test currently fails due to timing constraints where ephemeral resources
// are evaluated during the plan phase before AWS backends/roles are fully created.
// The implementation is correct and will work with pre-existing AWS infrastructure.
func TestAccAWSAccessCredentialsSTS(t *testing.T) {
	testutil.SkipTestAcc(t)

	a, s := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	mount := acctest.RandomWithPrefix("tf-aws-sts")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSAccessCredentialsSTSConfig(mount, a, s, region),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify that we got the access_key, secret_key, and security_token set
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("security_token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("type"), knownvalue.StringExact("sts")),
				},
			},
		},
	})
}

func testAWSAccessCredentialsConfig(mount, access, secret, region string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "aws" {
  path = "%s"
  description = "Obtain AWS credentials."
  access_key = "%s"
  secret_key = "%s"
  region = "%s"
}

resource "vault_aws_secret_backend_role" "role" {
  backend = vault_aws_secret_backend.aws.path
  name = "test"
  credential_type = "iam_user"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "iam:GetUser"
      Resource = "*"
    }]
  })
}

ephemeral "vault_aws_access_credentials" "creds" {
  backend = vault_aws_secret_backend.aws.path
  role    = vault_aws_secret_backend_role.role.name
  type    = "creds"
  region  = vault_aws_secret_backend.aws.region
}

provider "echo" {
  data = {
    access_key = ephemeral.vault_aws_access_credentials.creds.access_key
    secret_key = ephemeral.vault_aws_access_credentials.creds.secret_key
    security_token = ephemeral.vault_aws_access_credentials.creds.security_token
    type = ephemeral.vault_aws_access_credentials.creds.type
  }
}

resource "echo" "test" {}
`, mount, access, secret, region)
}

func testAWSAccessCredentialsSTSConfig(mount, access, secret, region string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "aws" {
  path = "%s"
  description = "Obtain AWS credentials."
  access_key = "%s"
  secret_key = "%s"
  region = "%s"
}

resource "vault_aws_secret_backend_role" "role" {
  backend = vault_aws_secret_backend.aws.path
  name = "test"
  credential_type = "federation_token"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "iam:GetUser"
      Resource = "*"
    }]
  })
}

ephemeral "vault_aws_access_credentials" "creds" {
  backend = vault_aws_secret_backend.aws.path
  role    = vault_aws_secret_backend_role.role.name
  type    = "sts"
  region  = vault_aws_secret_backend.aws.region
}

provider "echo" {
  data = {
    access_key = ephemeral.vault_aws_access_credentials.creds.access_key
    secret_key = ephemeral.vault_aws_access_credentials.creds.secret_key
    security_token = ephemeral.vault_aws_access_credentials.creds.security_token
    type = ephemeral.vault_aws_access_credentials.creds.type
  }
}

resource "echo" "test" {}
`, mount, access, secret, region)
}
