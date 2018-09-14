package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
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
						"bound_iam_principal_arn", "arn:aws:iam::123456789012:role/MyRole/*"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"ttl", "30"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"max_ttl", "60"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"policies.#", "2"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"policies.0", "default"),
					resource.TestCheckResourceAttr("vault_aws_auth_backend_role.role",
						"policies.1", "dev"),
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

		attrs := map[string]string{
			"auth_type":                      "auth_type",
			"bound_ami_id":                   "bound_ami_id",
			"bound_account_id":               "bound_account_id",
			"bound_region":                   "bound_region",
			"bound_vpc_id":                   "bound_vpc_id",
			"bound_subnet_id":                "bound_subnet_id",
			"bound_iam_role_arn":             "bound_iam_role_arn",
			"bound_iam_instance_profile_arn": "bound_iam_instance_profile_arn",
			"role_tag":                       "role_tag",
			"bound_iam_principal_arn":        "bound_iam_principal_arn",
			"inferred_entity_type":           "inferred_entity_type",
			"inferred_aws_region":            "inferred_aws_region",
			"resolve_aws_unique_ids":         "resolve_aws_unique_ids",
			"ttl":                            "ttl",
			"max_ttl":                        "max_ttl",
			"period":                         "period",
			"policies":                       "policies",
			"allow_instance_migration":       "allow_instance_migration",
			"disallow_reauthentication":      "disallow_reauthentication",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected API field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}
			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
					}
					for i := 0; i < count; i++ {
						stateData := instanceState.Attributes[stateAttr+"."+strconv.Itoa(i)]
						if stateData != apiData[i] {
							return fmt.Errorf("expected item %d of %s (%s in state) of %q to be %q, got %q", i, apiAttr, stateAttr, endpoint, stateData, apiData[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
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
  backend = "${vault_auth_backend.aws.path}"
  role = "%s"
  auth_type = "iam"
  bound_ami_id = "ami-8c1be5f6"
  bound_account_id = "123456789012"
  bound_vpc_id = "vpc-b61106d4"
  bound_subnet_id = "vpc-a33128f1"
  bound_iam_role_arn = "arn:aws:iam::123456789012:role/S3Access"
  bound_iam_instance_profile_arn = "arn:aws:iam::123456789012:instance-profile/Webserver"
  inferred_entity_type = "ec2_instance"
  inferred_aws_region = "us-east-1"
  ttl = 60
  max_ttl = 120
  policies = ["default", "dev", "prod"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_iam(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_role" "role" {
  backend = "${vault_auth_backend.aws.path}"
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arn = "arn:aws:iam::123456789012:role/*"
  resolve_aws_unique_ids = true
  ttl = 60
  max_ttl = 120
  policies = ["default", "dev", "prod"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_iamUpdate(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_role" "role" {
  backend = "${vault_auth_backend.aws.path}"
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arn = "arn:aws:iam::123456789012:role/MyRole/*"
  resolve_aws_unique_ids = true
  ttl = 30
  max_ttl = 60
  policies = ["default", "dev"]
}`, backend, role)
}

func testAccAWSAuthBackendRoleConfig_ec2(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_role" "role" {
  backend = "${vault_auth_backend.aws.path}"
  role = "%s"
  auth_type = "ec2"
  bound_ami_id = "ami-8c1be5f6"
  bound_account_id = "123456789012"
  bound_region = "us-east-1"
  bound_vpc_id = "vpc-b61106d4"
  bound_subnet_id = "vpc-a33128f1"
  bound_iam_role_arn = "arn:aws:iam::123456789012:role/S3Access"
  bound_iam_instance_profile_arn = "arn:aws:iam::123456789012:instance-profile/Webserver"
  role_tag = "VaultRoleTag"
  allow_instance_migration = true
  disallow_reauthentication = true
  ttl = 60
  max_ttl = 120
  policies = ["default", "dev", "prod"]
}`, backend, role)
}
