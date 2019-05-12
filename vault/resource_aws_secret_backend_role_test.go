package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

const testAccAWSSecretBackendRolePolicyInline_basic = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "iam:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyInline_updated = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "ec2:*","Resource": "*"}]}`
const testAccAWSSecretBackendRolePolicyArn_basic = "arn:aws:iam::123456789123:policy/foo"
const testAccAWSSecretBackendRolePolicyArn_updated = "arn:aws:iam::123456789123:policy/bar"
const testAccAWSSecretBackendRoleAssumedRoleArn_basic = "arn:aws:iam::123456789123:role/aws-service-role/organizations.amazonaws.com/foo"
const testAccAWSSecretBackendRoleAssumedRoleArn_updated = "arn:aws:iam::123456789123:role/aws-service-role/organizations.amazonaws.com/bar"
const default_sts_ttl = "1800"
const max_sts_ttl = "5400"

func TestAccAWSSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "default_sts_ttl", default_sts_ttl),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "name", fmt.Sprintf("%s-assumed-roles-arns-with-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "default_sts_ttl", default_sts_ttl),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "name", fmt.Sprintf("%s-assumed-roles-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "default_sts_ttl", default_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "default_sts_ttl", default_sts_ttl),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "name", fmt.Sprintf("%s-assumed-roles-arns-with-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "default_sts_ttl", default_sts_ttl),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "name", fmt.Sprintf("%s-assumed-roles-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "default_sts_ttl", default_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
				),
			},
		},
	})
}

func TestAccAWSSecretBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "default_sts_ttl", default_sts_ttl),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "name", fmt.Sprintf("%s-assumed-roles-arns-with-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "default_sts_ttl", default_sts_ttl),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "name", fmt.Sprintf("%s-assumed-roles-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "default_sts_ttl", default_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
				),
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_inline",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_arns",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_assumed_roles_arns",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_aws_secret_backend_role.test_policy_inline_and_arns",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSSecretBackendRole_nested(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-aws/nested")
	name := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAWSSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "default_sts_ttl", default_sts_ttl),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "name", fmt.Sprintf("%s-assumed-roles-arns-with-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "default_sts_ttl", default_sts_ttl),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_basic),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "name", fmt.Sprintf("%s-assumed-roles-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_basic),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "default_sts_ttl", default_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_basic),
				),
			},
			{
				Config: testAccAWSSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "name", fmt.Sprintf("%s-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "name", fmt.Sprintf("%s-policy-arn", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "backend", backend),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_policy_inline_and_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "name", fmt.Sprintf("%s-policy-inline-and-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns", "default_sts_ttl", default_sts_ttl),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "name", fmt.Sprintf("%s-assumed-roles-arns-with-policy-inline", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "default_sts_ttl", default_sts_ttl),
					util.TestCheckResourceAttrJSON("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_inline", "policy_document", testAccAWSSecretBackendRolePolicyInline_updated),

					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "name", fmt.Sprintf("%s-assumed-roles-arns", name)),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "backend", backend),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "role_arns.0", testAccAWSSecretBackendRoleAssumedRoleArn_updated),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "credential_type", "assumed_role"),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "max_sts_ttl", max_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "default_sts_ttl", default_sts_ttl),
					resource.TestCheckResourceAttr("vault_aws_secret_backend_role.test_assumed_roles_arns_with_policy_arns", "policy_arns.0", testAccAWSSecretBackendRolePolicyArn_updated),
				),
			},
		},
	})
}

func testAccAWSSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_secret_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAWSSecretBackendRoleConfig_basic(name, path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_backend_role" "test_policy_inline" {
  name = "%s-policy-inline"
  policy_document = %q
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arn"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_inline_and_arns" {
  name = "%s-policy-inline-and-arns"
  policy_document = %q
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_assumed_roles_arns" {
  name = "%s-assumed-roles-arns"
  role_arns = ["%s"]
  credential_type = "assumed_role"
  backend = "${vault_aws_secret_backend.test.path}"
  max_sts_ttl = "%s"
  default_sts_ttl = "%s"
}
 resource "vault_aws_secret_backend_role" "test_credential_type_migration" {
  name = "%s-type-migration"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_assumed_roles_arns_with_policy_inline" {
  name = "%s-assumed-roles-arns-with-policy-inline"
  role_arns = ["%s"]
  credential_type = "assumed_role"
  backend = "${vault_aws_secret_backend.test.path}"
  max_sts_ttl = "%s"
  default_sts_ttl = "%s"
  policy_document = %q
}

resource "vault_aws_secret_backend_role" "test_assumed_roles_arns_with_policy_arns" {
  name = "%s-assumed-roles-arns-with-policy-arns"
  role_arns = ["%s"]
  credential_type = "assumed_role"
  backend = "${vault_aws_secret_backend.test.path}"
  max_sts_ttl = "%s"
  default_sts_ttl = "%s"
  policy_arns = ["%s"]
}
 `, path, accessKey, secretKey,
		name, testAccAWSSecretBackendRolePolicyInline_basic,
		name, testAccAWSSecretBackendRolePolicyArn_basic,
		name, testAccAWSSecretBackendRolePolicyInline_basic, testAccAWSSecretBackendRolePolicyArn_basic,
		name, testAccAWSSecretBackendRoleAssumedRoleArn_basic, max_sts_ttl, default_sts_ttl,
		name, testAccAWSSecretBackendRolePolicyArn_basic,
		name, testAccAWSSecretBackendRoleAssumedRoleArn_basic, max_sts_ttl, default_sts_ttl, testAccAWSSecretBackendRolePolicyInline_basic,
		name, testAccAWSSecretBackendRoleAssumedRoleArn_basic, max_sts_ttl, default_sts_ttl, testAccAWSSecretBackendRolePolicyArn_basic,
	)
}

func testAccAWSSecretBackendRoleConfig_updated(name, path, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "test" {
  path = "%s"
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_secret_backend_role" "test_policy_inline" {
  name = "%s-policy-inline"
  policy_document = %q
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_arns" {
  name = "%s-policy-arn"
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}

resource "vault_aws_secret_backend_role" "test_policy_inline_and_arns" {
  name = "%s-policy-inline-and-arns"
  policy_document = %q
  policy_arns = ["%s"]
  credential_type = "iam_user"
  backend = "${vault_aws_secret_backend.test.path}"
}
resource "vault_aws_secret_backend_role" "test_assumed_roles_arns" {
  name = "%s-assumed-roles-arns"
  role_arns = ["%s"]
  credential_type = "assumed_role"
  backend = "${vault_aws_secret_backend.test.path}"
}
 resource "vault_aws_secret_backend_role" "test_credential_type_migration" {
  name = "%s-type-migration"
  role_arns = ["%s"]
  credential_type = "assumed_role"
  backend = "${vault_aws_secret_backend.test.path}"
  max_sts_ttl = "%s"
  default_sts_ttl = "%s"
}

resource "vault_aws_secret_backend_role" "test_assumed_roles_arns_with_policy_inline" {
  name = "%s-assumed-roles-arns-with-policy-inline"
  role_arns = ["%s"]
  credential_type = "assumed_role"
  backend = "${vault_aws_secret_backend.test.path}"
  max_sts_ttl = "%s"
  default_sts_ttl = "%s"
  policy_document = %q
}

resource "vault_aws_secret_backend_role" "test_assumed_roles_arns_with_policy_arns" {
  name = "%s-assumed-roles-arns-with-policy-arns"
  role_arns = ["%s"]
  credential_type = "assumed_role"
  backend = "${vault_aws_secret_backend.test.path}"
  max_sts_ttl = "%s"
  default_sts_ttl = "%s"
  policy_arns = ["%s"]
}
`, path, accessKey, secretKey,
		name, testAccAWSSecretBackendRolePolicyInline_updated,
		name, testAccAWSSecretBackendRolePolicyArn_updated,
		name, testAccAWSSecretBackendRolePolicyInline_updated, testAccAWSSecretBackendRolePolicyArn_updated,
		name, testAccAWSSecretBackendRoleAssumedRoleArn_updated,
		name, testAccAWSSecretBackendRoleAssumedRoleArn_updated, max_sts_ttl, default_sts_ttl,
		name, testAccAWSSecretBackendRoleAssumedRoleArn_updated, max_sts_ttl, default_sts_ttl, testAccAWSSecretBackendRolePolicyInline_updated,
		name, testAccAWSSecretBackendRoleAssumedRoleArn_updated, max_sts_ttl, default_sts_ttl, testAccAWSSecretBackendRolePolicyArn_updated,
	)
}
