package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccAWSAuthBackendClient_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendClientDestroy,
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
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckAWSAuthBackendClientDestroy,
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
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckAWSAuthBackendClientDestroy,
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
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_basicWithoutSecretKey(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendClientCheck_attrs(backend),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_client.client", "access_key", "AWSACCESSKEY"),
					resource.TestCheckNoResourceAttr("vault_aws_auth_backend_client.client", "secret_key"),
				),
			},
			{
				Config: testAccAWSAuthBackendClientConfig_updatedWithoutSecretKey(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendClientCheck_attrs(backend),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_client.client", "access_key", "AWSACCESSKEY"),
					resource.TestCheckNoResourceAttr("vault_aws_auth_backend_client.client", "secret_key"),
				),
			},
		},
	})
}

func TestAccAWSAuthBackendClientStsRegionNoEndpoint(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccAWSAuthBackendClientConfigSTSRegionNoEndpoint(backend),
				ExpectError: regexp.MustCompile("Error: both sts_endpoint and sts_region need to be set"),
			},
		},
	})
}

func testAccCheckAWSAuthBackendClientDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_client" {
			continue
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

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back AWS auth client config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("AWS auth client not configured at %q", endpoint)
		}
		attrs := map[string]string{
			"access_key": "access_key",
			//"secret_key":                 "secret_key",
			"ec2_endpoint":               "endpoint",
			"iam_endpoint":               "iam_endpoint",
			"sts_endpoint":               "sts_endpoint",
			"sts_region":                 "sts_region",
			"iam_server_id_header_value": "iam_server_id_header_value",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			if resp.Data[apiAttr] != instanceState.Attributes[stateAttr] {
				return fmt.Errorf("expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
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
