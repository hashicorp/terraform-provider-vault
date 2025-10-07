// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAWSAuthBackendSTSRole_withExternalID(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	accountID := strconv.Itoa(acctest.RandInt())
	arn := acctest.RandomWithPrefix("arn:aws:iam::" + accountID + ":role/test-role")
	externalID := "external-id"
	updatedExternalID := "external-id-updated"
	resourceName := "vault_aws_auth_backend_sts_role.role"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendSTSRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendSTSRoleConfig(backend, accountID, arn, externalID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "sts_role", arn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, externalID),
				),
			},
			{
				// Update external ID.
				Config: testAccAWSAuthBackendSTSRoleConfig(backend, accountID, arn, updatedExternalID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "account_id", accountID),
					resource.TestCheckResourceAttr(resourceName, "sts_role", arn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, updatedExternalID),
				),
			},
			{
				ResourceName:      resourceName,
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
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAWSAuthBackendSTSRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendSTSRoleConfig(backend, accountID, arn, ""),
				Check:  testAccAWSAuthBackendSTSRoleCheck_attrs(backend, accountID, arn),
			},
			{
				// Update ARN.
				Config: testAccAWSAuthBackendSTSRoleConfig(backend, accountID, updatedArn, ""),
				Check:  testAccAWSAuthBackendSTSRoleCheck_attrs(backend, accountID, updatedArn),
			},
			{
				ResourceName:      "vault_aws_auth_backend_sts_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckAWSAuthBackendSTSRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_sts_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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

		client, e := provider.GetClient(instanceState, testProvider.Meta())
		if e != nil {
			return e
		}

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

func testAccAWSAuthBackendSTSRoleConfig(backend, accountID, stsRole, externalID string) string {
	backendResource := fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
	type = "aws"
	path = "%s"
}`, backend)

	roleResourceOptionalFields := ""
	if externalID != "" {
		roleResourceOptionalFields += fmt.Sprintf(`
	external_id = "%s"`, externalID)
	}

	roleResource := fmt.Sprintf(`
resource "vault_aws_auth_backend_sts_role" "role" {
	backend = vault_auth_backend.aws.path
	account_id = "%s"
	sts_role = "%s"%s
}
`, accountID, stsRole, roleResourceOptionalFields)

	resources := []string{backendResource, roleResource}

	return strings.Join(resources, "\n")
}
