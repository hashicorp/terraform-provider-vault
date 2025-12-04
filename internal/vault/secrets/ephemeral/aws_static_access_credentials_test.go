// Copyright IBM Corp. 2016, 2025
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
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccAWSStaticAccessCredentials confirms that AWS static credentials
// are correctly read from Vault into the ephemeral resource
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccAWSStaticAccessCredentials(t *testing.T) {
	testutil.SkipTestAcc(t)

	a, s := testutil.GetTestAWSCreds(t)
	username := testutil.SkipTestEnvUnset(t, "AWS_STATIC_USER")[0]
	mount := acctest.RandomWithPrefix("tf-aws-static")

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
				Config: testAWSStaticAccessCredentialsConfig(mount, a, s, username),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify that we got the access_key and secret_key set
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldAccessKey), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldSecretKey), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAWSStaticAccessCredentialsConfig(mount, access, secret, username string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "aws" {
  path = "%s"
  description = "Obtain AWS credentials."
  access_key = "%s"
  secret_key = "%s"
  region = "us-east-1"
}

resource "vault_aws_secret_backend_static_role" "role" {
  backend = vault_aws_secret_backend.aws.path
  name = "test"
  username = "%s"
  rotation_period = "3600"
}

ephemeral "vault_aws_static_access_credentials" "creds" {
  mount = vault_aws_secret_backend.aws.path
  name    = vault_aws_secret_backend_static_role.role.name
  mount_id = vault_aws_secret_backend_static_role.role.id
}

provider "echo" {
  data = ephemeral.vault_aws_static_access_credentials.creds
}

resource "echo" "test" {}
`, mount, access, secret, username)
}
