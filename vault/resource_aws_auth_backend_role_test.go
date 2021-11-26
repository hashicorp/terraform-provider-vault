package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccAWSAuthBackendRole_importInferred(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_inferred(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(backend, role),
			},
			{
				ResourceName:      "vault_aws_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"bound_ami_id", "bound_account_id", "bound_region",
					"bound_vpc_id", "bound_subnet_id", "bound_iam_role_arn",
					"bound_iam_instance_profile_arn", "bound_ec2_instance_id",
					"bound_iam_principal_arn"},
			},
		},
	})
}

func TestAccAWSAuthBackendRole_importEC2(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_ec2(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(backend, role),
			},
			{
				ResourceName:      "vault_aws_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAuthBackendRole_importIAM(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_iam(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(backend, role),
			},
			{
				ResourceName:      "vault_aws_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAuthBackendRole_inferred(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_inferred(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(backend, role),
			},
		},
	})
}

func TestAccAWSAuthBackendRole_ec2(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_ec2(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(backend, role),
			},
		},
	})
}

func TestAccAWSAuthBackendRole_iam(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_iam(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(backend, role),
			},
		},
	})
}

func TestAccAWSAuthBackendRole_iam_resolve_aws_unique_ids(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_iam_resolve_aws_unique_ids(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(backend, role),
			},
		},
	})
}

func TestAccAWSAuthBackendRole_iamUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendRoleConfig_iam(backend, role),
				Check:  testAccAWSAuthBackendRoleCheck_attrs(backend, role),
			},
			{
				Config: testAccAWSAuthBackendRoleConfig_iamUpdate(backend, role),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendRoleCheck_attrs(backend, role),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"bound_iam_principal_arns.#", "1"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"bound_iam_principal_arns.0", "arn:aws:iam::123456789012:role/MyRole/*"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_ttl", "30"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_max_ttl", "60"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_policies.1", "dev"),
				),
			},
			{
				Config: testAccAWSAuthBackendRoleConfig_DeletePolicies(backend, role),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendRoleCheck_attrs(backend, role),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_policies.#", "0"),
				),
			},
			{
				Config: testAccAWSAuthBackendRoleConfig_Unset(backend, role),
				Check: resource.ComposeTestCheckFunc(
					testAccAWSAuthBackendRoleCheck_attrs(backend, role),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_policies.#", "0"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"token_max_ttl", "0"),
				),
			},
		},
	})
}

func testAccCheckAWSAuthBackendRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AWS auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AWS auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAWSAuthBackendRoleCheck_attrs(backend, role string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_aws_auth_backend_role.role"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/"+backend+"/role/"+role {
			return fmt.Errorf("expected ID to be %q, got %q instead", "auth/"+backend+"/role/"+role, endpoint)
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", endpoint)
		}

		attrs := []*fieldNames{
			{NameInVault: "auth_type", NameInProvider: "auth_type"},
			{NameInVault: "bound_ami_id", NameInProvider: "bound_ami_ids", PreviousNameInProvider: "bound_ami_id"},
			{NameInVault: "bound_account_id", NameInProvider: "bound_account_ids", PreviousNameInProvider: "bound_account_id"},
			{NameInVault: "bound_region", NameInProvider: "bound_regions", PreviousNameInProvider: "bound_region"},
			{NameInVault: "bound_vpc_id", NameInProvider: "bound_vpc_ids", PreviousNameInProvider: "bound_vpc_id"},
			{NameInVault: "bound_subnet_id", NameInProvider: "bound_subnet_ids", PreviousNameInProvider: "bound_subnet_id"},
			{NameInVault: "bound_iam_role_arn", NameInProvider: "bound_iam_role_arns", PreviousNameInProvider: "bound_iam_role_arn"},
			{NameInVault: "bound_iam_instance_profile_arn", NameInProvider: "bound_iam_instance_profile_arns", PreviousNameInProvider: "bound_iam_instance_profile_arn"},
			{NameInVault: "bound_ec2_instance_id", NameInProvider: "bound_ec2_instance_ids", PreviousNameInProvider: "bound_ec2_instance_id"},
			{NameInVault: "role_tag", NameInProvider: "role_tag"},
			{NameInVault: "bound_iam_principal_arn", NameInProvider: "bound_iam_principal_arns", PreviousNameInProvider: "bound_iam_principal_arn"},
			{NameInVault: "inferred_entity_type", NameInProvider: "inferred_entity_type"},
			{NameInVault: "inferred_aws_region", NameInProvider: "inferred_aws_region"},
			{NameInVault: "resolve_aws_unique_ids", NameInProvider: "resolve_aws_unique_ids"},
			{NameInVault: "token_ttl", NameInProvider: "token_ttl"},
			{NameInVault: "token_max_ttl", NameInProvider: "token_max_ttl"},
			{NameInVault: "token_period", NameInProvider: "token_period"},
			{NameInVault: "token_policies", NameInProvider: "token_policies"},
			{NameInVault: "allow_instance_migration", NameInProvider: "allow_instance_migration"},
			{NameInVault: "disallow_reauthentication", NameInProvider: "disallow_reauthentication"},
		}
		for _, attr := range attrs {

			providerValIsArray := true
			stateAttr := ""
			if _, ok := instanceState.Attributes[attr.NameInProvider]; ok {
				providerValIsArray = false
				stateAttr = attr.NameInProvider
			} else if _, ok := instanceState.Attributes[attr.PreviousNameInProvider]; ok {
				providerValIsArray = false
				stateAttr = attr.PreviousNameInProvider
			} else if _, ok := instanceState.Attributes[attr.NameInProvider+".#"]; ok {
				stateAttr = attr.NameInProvider
			} else if _, ok := instanceState.Attributes[attr.PreviousNameInProvider+".#"]; ok {
				stateAttr = attr.PreviousNameInProvider
			}
			stateAttrVal := instanceState.Attributes[stateAttr]

			if resp.Data[attr.NameInVault] == nil && stateAttrVal == "" {
				continue
			}
			var match bool
			switch vaultRespVal := resp.Data[attr.NameInVault].(type) {
			case json.Number:
				apiData, err := vaultRespVal.Int64()
				if err != nil {
					return fmt.Errorf("expected API field %s to be an int, was %q", attr.NameInVault, resp.Data[attr.NameInVault])
				}
				stateData, err := strconv.ParseInt(stateAttrVal, 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, stateAttrVal)
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[attr.NameInVault]; !ok && stateAttrVal == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(stateAttrVal)
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, stateAttrVal)
					}
					match = vaultRespVal == stateData
				}
			case []interface{}:
				length := instanceState.Attributes[stateAttr+".#"]
				if !providerValIsArray {
					if len(vaultRespVal) != 1 {
						return fmt.Errorf("expected one response value but received %s", vaultRespVal)
					}
					if vaultRespVal[0] != stateAttrVal {
						return fmt.Errorf("expected %s but received %s", stateAttrVal, vaultRespVal[0])
					}
					match = true
				} else if length == "" {
					if len(vaultRespVal) != 0 {
						return fmt.Errorf("expected state field %s to have %d entries, had 0", stateAttr, len(vaultRespVal))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(vaultRespVal) {
						return fmt.Errorf("expected %s to have %d entries in state, has %d", stateAttr, len(vaultRespVal), count)
					}
					for i := 0; i < count; i++ {
						found := false
						for stateKey, stateValue := range instanceState.Attributes {
							if strings.HasPrefix(stateKey, stateAttr) {
								if vaultRespVal[i] == stateValue {
									found = true
									break
								}
							}
						}
						if !found {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, attr.NameInVault, stateAttr, vaultRespVal[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[attr.NameInVault] == stateAttrVal
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", attr.NameInVault, stateAttr, endpoint, stateAttrVal, resp.Data[attr.NameInVault])
			}
		}
		return nil
	}
}

func testAccAWSAuthBackendRoleConfig_inferred(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_ami_ids = ["ami-8c1be5f6"]
  bound_account_ids = ["123456789012"]
  bound_vpc_ids = ["vpc-b61106d4"]
  bound_subnet_ids = ["vpc-a33128f1"]
  bound_iam_role_arns = ["arn:aws:iam::123456789012:role/S3Access"]
  bound_iam_instance_profile_arns = ["arn:aws:iam::123456789012:instance-profile/Webserver"]
  bound_ec2_instance_ids = ["i-06bb291939760ba66"]
  inferred_entity_type = "ec2_instance"
  inferred_aws_region = "us-east-1"
  token_ttl = 60
  token_max_ttl = 120
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_iam(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/*"]
  resolve_aws_unique_ids = true
  token_ttl = 60
  token_max_ttl = 120
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_iam_resolve_aws_unique_ids(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/*"]
  resolve_aws_unique_ids = false
  token_ttl = 60
  token_max_ttl = 120
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_iamUpdate(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/MyRole/*"]
  resolve_aws_unique_ids = true
  token_ttl = 30
  token_max_ttl = 60
  token_policies = ["default", "dev"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_DeletePolicies(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/MyRole/*"]
  resolve_aws_unique_ids = true
  token_ttl = 30
  token_max_ttl = 60
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_Unset(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::123456789012:role/MyRole/*"]
  resolve_aws_unique_ids = true
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_ec2(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}
resource "vault_aws_auth_backend_role" "role" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "ec2"
  bound_ami_ids = ["ami-8c1be5f6"]
  bound_account_ids = ["123456789012"]
  bound_regions = ["us-east-1"]
  bound_vpc_ids = ["vpc-b61106d4"]
  bound_subnet_ids = ["vpc-a33128f1"]
  bound_iam_role_arns = ["arn:aws:iam::123456789012:role/S3Access"]
  bound_iam_instance_profile_arns = ["arn:aws:iam::123456789012:instance-profile/Webserver"]
  bound_ec2_instance_ids = ["i-06bb291939760ba66"]
  role_tag = "VaultRoleTag"
  disallow_reauthentication = true
  token_ttl = 60
  token_max_ttl = 120
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
}

type fieldNames struct {
	NameInVault            string
	NameInProvider         string
	PreviousNameInProvider string
}
