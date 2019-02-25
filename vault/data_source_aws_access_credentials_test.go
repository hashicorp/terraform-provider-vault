package vault

import (
	"fmt"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccDataSourceAWSAccessCredentials_basic(t *testing.T) {
	mountPath := acctest.RandomWithPrefix("tf-test-aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAWSAccessCredentialsConfig_basic(mountPath, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_aws_access_credentials.test", "access_key"),
					resource.TestCheckResourceAttrSet("data.vault_aws_access_credentials.test", "secret_key"),
					resource.TestCheckResourceAttr("data.vault_aws_access_credentials.test", "security_token", ""),
					resource.TestCheckResourceAttr("data.vault_aws_access_credentials.test", "type", "creds"),
					resource.TestCheckResourceAttrSet("data.vault_aws_access_credentials.test", "lease_id"),
					testAccDataSourceAWSAccessCredentialsCheck_tokenWorks(mountPath),
				),
			},
		},
	})
}

func TestAccDataSourceAWSAccessCredentials_sts(t *testing.T) {
	mountPath := acctest.RandomWithPrefix("aws")
	accessKey, secretKey := getTestAWSCreds(t)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAWSAccessCredentialsConfig_sts(mountPath, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_aws_access_credentials.test", "access_key"),
					resource.TestCheckResourceAttrSet("data.vault_aws_access_credentials.test", "secret_key"),
					resource.TestCheckResourceAttrSet("data.vault_aws_access_credentials.test", "security_token"),
					resource.TestCheckResourceAttr("data.vault_aws_access_credentials.test", "type", "sts"),
					resource.TestCheckResourceAttrSet("data.vault_aws_access_credentials.test", "lease_id"),
					testAccDataSourceAWSAccessCredentialsCheck_tokenWorks(mountPath),
				),
			},
		},
	})
}

func testAccDataSourceAWSAccessCredentialsConfig_basic(mountPath, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "aws" {
    path = "%s"
    description = "Obtain AWS credentials."
    access_key = "%s"
    secret_key = "%s"
}

resource "vault_aws_secret_backend_role" "role" {
    backend = "${vault_aws_secret_backend.aws.path}"
    name = "test"
    credential_type = "iam_user"
    policy_document = "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\"}]}"
}

data "vault_aws_access_credentials" "test" {
    backend = "${vault_aws_secret_backend.aws.path}"
    role = "${vault_aws_secret_backend_role.role.name}"
    type = "creds"
}`, mountPath, accessKey, secretKey)
}

func testAccDataSourceAWSAccessCredentialsConfig_sts(mountPath, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "aws" {
    path = "%s"
    description = "Obtain AWS credentials."
    access_key = "%s"
    secret_key = "%s"
}

resource "vault_aws_secret_backend_role" "role" {
    backend = "${vault_aws_secret_backend.aws.path}"
    name = "test"
	credential_type = "federation_token"
    policy_document = "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\"}]}"
}

data "vault_aws_access_credentials" "test" {
    backend = "${vault_aws_secret_backend.aws.path}"
    role = "${vault_aws_secret_backend_role.role.name}"
    type = "sts"
}`, mountPath, accessKey, secretKey)
}

func testAccDataSourceAWSAccessCredentialsCheck_tokenWorks(mountPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["data.vault_aws_access_credentials.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
		}

		iState := resourceState.Primary
		if iState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		accessKey := iState.Attributes["access_key"]
		secretKey := iState.Attributes["secret_key"]
		credType := iState.Attributes["type"]
		securityToken := iState.Attributes["security_token"]

		awsConfig := &aws.Config{
			Credentials: credentials.NewStaticCredentials(accessKey, secretKey, securityToken),
			HTTPClient:  cleanhttp.DefaultClient(),
		}
		sess, err := session.NewSession(awsConfig)
		if err != nil {
			return fmt.Errorf("error creating new session: %s", err)
		}

		switch credType {
		case "creds":
			conn := iam.New(sess)
			user, err := conn.GetUser(nil)
			if err != nil {
				return fmt.Errorf("error retrieving credentials user: %s", err)
			}
			log.Printf("[DEBUG] User: %+v", user)
		case "sts":
			conn := sts.New(sess)
			resp, err := conn.GetCallerIdentity(nil)
			if err != nil {
				return fmt.Errorf("error retrieving STS user: %s", err)
			}
			log.Printf("[DEBUG] STS resp: %+v", resp)
		default:
			return fmt.Errorf("unrecognised credentials type %q", credType)
		}
		return nil
	}
}
