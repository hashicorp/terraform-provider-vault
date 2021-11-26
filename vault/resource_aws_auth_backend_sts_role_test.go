package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccAWSAuthBackendSTSRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	accountID := strconv.Itoa(acctest.RandInt())
	arn := acctest.RandomWithPrefix("arn:aws:iam::" + accountID + ":role/test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendSTSRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendSTSRoleConfig_basic(backend, accountID, arn),
				Check:  testAccAWSAuthBackendSTSRoleCheck_attrs(backend, accountID, arn),
			},
			{
				ResourceName:      "vault_aws_auth_backend_sts_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAuthBackendSTSRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	accountID := strconv.Itoa(acctest.RandInt())
	arn := acctest.RandomWithPrefix("arn:aws:iam::" + accountID + ":role/test-role")
	updatedArn := acctest.RandomWithPrefix("arn:aws:iam::" + accountID + ":role/test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendSTSRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendSTSRoleConfig_basic(backend, accountID, arn),
				Check:  testAccAWSAuthBackendSTSRoleCheck_attrs(backend, accountID, arn),
			},
			{
				Config: testAccAWSAuthBackendSTSRoleConfig_basic(backend, accountID, updatedArn),
				Check:  testAccAWSAuthBackendSTSRoleCheck_attrs(backend, accountID, updatedArn),
			},
		},
	})
}

func testAccCheckAWSAuthBackendSTSRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_sts_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for AWS auth backend STS role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AWS auth backend STS role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAWSAuthBackendSTSRoleCheck_attrs(backend, accountID, stsRole string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_aws_auth_backend_sts_role.role"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance state")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/"+backend+"/config/sts/"+accountID {
			return fmt.Errorf("expected ID to be %q, got %q instead", "auth/"+backend+"/config/sts/"+accountID, endpoint)
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back sts role from %q: %s", endpoint, err)
		}

		if resp == nil {
			return fmt.Errorf("%q doesn't exist", endpoint)
		}

		attrs := map[string]string{
			"sts_role": "sts_role",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			if resp.Data[apiAttr] != instanceState.Attributes[stateAttr] {
				return fmt.Errorf("Expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testAccAWSAuthBackendSTSRoleConfig_basic(backend, accountID, stsRole string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_sts_role" "role" {
  backend = vault_auth_backend.aws.path
  account_id = "%s"
  sts_role = "%s"
}
`, backend, accountID, stsRole)
}
