package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAwsAuthBackendConfigIdentity(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resourceName := "vault_aws_auth_backend_config_identity.config"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAwsAuthBackendConfigIdentityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAwsAuthBackendConfigIdentity_basic(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "iam_alias", "unique_id"),
					resource.TestCheckResourceAttr(resourceName, "iam_metadata.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "iam_metadata.0", "client_arn"),
					resource.TestCheckResourceAttr(resourceName, "iam_metadata.1", "inferred_aws_region"),
					resource.TestCheckResourceAttr(resourceName, "ec2_alias", "role_id"),
					resource.TestCheckResourceAttr(resourceName, "ec2_metadata.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "ec2_metadata.0", "account_id"),
					resource.TestCheckResourceAttr(resourceName, "ec2_metadata.1", "auth_type"),
				),
			},
			{
				Config: testAccAwsAuthBackendConfigIdentity_updated(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "iam_alias", "full_arn"),
					resource.TestCheckResourceAttr(resourceName, "iam_metadata.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "iam_metadata.0", "client_user_id"),
					resource.TestCheckResourceAttr(resourceName, "ec2_alias", "role_id"),
					resource.TestCheckResourceAttr(resourceName, "ec2_metadata.#", "0"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testAccCheckAwsAuthBackendConfigIdentityDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_config_identity" {
			continue
		}
		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AWS auth backend %q config: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AWS auth backend %q still configured", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAwsAuthBackendConfigIdentity_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for AWS backend config"
}

resource "vault_aws_auth_backend_config_identity" "config" {
  backend = vault_auth_backend.aws.path
  iam_alias = "unique_id"
  iam_metadata = ["inferred_aws_region", "client_arn"]
  ec2_metadata = ["account_id", "auth_type"]
}
`, backend)
}

func testAccAwsAuthBackendConfigIdentityCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_aws_auth_backend_config_identity.config"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/"+backend+"/config/identity" {
			return fmt.Errorf("expected ID to be %q, got %q", "auth/"+backend+"/config/identity", endpoint)
		}

		client, e := provider.GetClient(instanceState, testProvider.Meta())
		if e != nil {
			return e
		}

		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back AWS auth identity config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("AWS auth not configured at %q", endpoint)
		}
		attrs := map[string]string{
			"iam_alias":    "iam_alias",
			"iam_metadata": "iam_metadata",
			"ec2_alias":    "ec2_alias",
			"ec2_metadata": "ec2_metadata",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}

			if stateStringVal, ok := instanceState.Attributes[stateAttr]; ok {
				if resp.Data[apiAttr] != stateStringVal {
					return fmt.Errorf("expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, stateStringVal, resp.Data[apiAttr])
				}
			} else if listLength, ok := instanceState.Attributes[stateAttr+".#"]; ok {
				compLen, _ := strconv.Atoi(listLength)
				for i := 0; i < compLen; i++ {
					stateVal := instanceState.Attributes[fmt.Sprintf("%s.%d", stateAttr, i)]
					respVal := resp.Data[apiAttr].([]interface{})[i]
					if respVal != stateVal {
						return fmt.Errorf("expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, stateVal, respVal)
					}
				}
			}
		}
		return nil
	}
}

func testAccAwsAuthBackendConfigIdentity_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend config"
}

resource "vault_aws_auth_backend_config_identity" "config" {
  backend = vault_auth_backend.aws.path
  iam_alias = "full_arn"
  iam_metadata = ["client_user_id"]
}`, backend)
}
