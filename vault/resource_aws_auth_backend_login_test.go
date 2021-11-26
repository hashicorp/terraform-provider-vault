package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccAWSAuthBackendLogin_iamIdentity(t *testing.T) {
	mountPath := acctest.RandomWithPrefix("tf-test-aws")
	roleName := acctest.RandomWithPrefix("tf-test")
	accessKey, secretKey := getTestAWSCreds(t)

	sess, err := session.NewSession(nil)
	if err != nil {
		t.Errorf("Error creating AWS session: %s", err)
	}
	stsService := sts.New(sess)
	testIdentity, err := stsService.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		t.Errorf("Error obtaining identity document: %s", err)
	}
	stsRequest, _ := stsService.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	stsRequest.Sign()
	loginDataHeaders, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		t.Errorf("Error marshaling login headers: %s", err)
	}
	loginDataBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		t.Errorf("Error reading login body: %s", err)
	}
	reqMethod := stsRequest.HTTPRequest.Method
	reqURL := base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	reqHeaders := base64.StdEncoding.EncodeToString(loginDataHeaders)
	reqBody := base64.StdEncoding.EncodeToString(loginDataBody)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAWSAuthBackendLoginConfig_iamIdentity(mountPath, accessKey, secretKey, reqMethod, reqURL, reqHeaders, reqBody, roleName, *testIdentity.Arn),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_login.test", "client_token"),
				),
			},
		},
	})
}

func TestAccAWSAuthBackendLogin_pkcs7(t *testing.T) {
	if os.Getenv("TF_AWS_META") == "" {
		t.Skip("Not running on EC2 instance, can't test EC2 auth methods")
	}

	mountPath := acctest.RandomWithPrefix("tf-test-aws")
	roleName := acctest.RandomWithPrefix("tf-test")
	accessKey, secretKey := getTestAWSCreds(t)

	sess, err := session.NewSession(nil)
	if err != nil {
		t.Errorf("Error creating AWS session: %s", err)
	}
	metadata := ec2metadata.New(sess)

	if !metadata.Available() {
		t.Skip("Not running on EC2 instance, can't test ec2 auth methods.")
	}

	iamInfo, err := metadata.IAMInfo()
	if err != nil {
		t.Errorf("Error retrieving IAM info for instance: %s", err)
	}
	arn := iamInfo.InstanceProfileArn

	doc, err := metadata.GetInstanceIdentityDocument()
	if err != nil {
		t.Errorf("Error retrieving instance identity document: %s", err)
	}
	ami := doc.ImageID
	account := doc.AccountID

	pkcs7, err := metadata.GetDynamicData("instance-identity/pkcs7")
	if err != nil {
		t.Errorf("Error retrieving pkcs7 signature: %s", err)
	}
	pkcs7 = strings.Replace(pkcs7, "\n", "", -1)

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAWSAuthBackendLoginConfig_pkcs7(mountPath, accessKey, secretKey, roleName, ami, account, arn, pkcs7),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_login.test", "client_token"),
				),
			},
		},
	})
}

func TestAccAWSAuthBackendLogin_ec2Identity(t *testing.T) {
	if os.Getenv("TF_AWS_META") == "" {
		t.Skip("Not running on EC2 instance, can't test EC2 auth methods")
	}

	mountPath := acctest.RandomWithPrefix("tf-test-aws")
	roleName := acctest.RandomWithPrefix("tf-test")
	accessKey, secretKey := getTestAWSCreds(t)

	sess, err := session.NewSession(nil)
	if err != nil {
		t.Errorf("Error creating AWS session: %s", err)
	}
	metadata := ec2metadata.New(sess)

	if !metadata.Available() {
		t.Skip("Not running on EC2 instance, can't test ec2 auth methods.")
	}

	iamInfo, err := metadata.IAMInfo()
	if err != nil {
		t.Errorf("Error retrieving IAM info for instance: %s", err)
	}
	arn := iamInfo.InstanceProfileArn

	doc, err := metadata.GetInstanceIdentityDocument()
	if err != nil {
		t.Errorf("Error retrieving instance identity document: %s", err)
	}
	ami := doc.ImageID
	account := doc.AccountID

	identity, err := metadata.GetDynamicData("instance-identity/document")
	if err != nil {
		t.Errorf("Error retrieving raw identity: %s", err)
	}
	identity = base64.StdEncoding.EncodeToString([]byte(identity))

	sig, err := metadata.GetDynamicData("instance-identity/signature")
	if err != nil {
		t.Errorf("Error retrieving signature: %s", err)
	}
	sig = strings.Replace(sig, "\n", "", -1)

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAWSAuthBackendLoginConfig_ec2Identity(mountPath, accessKey, secretKey, roleName, ami, account, arn, identity, sig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("vault_aws_auth_backend_login.test", "client_token"),
				),
			},
		},
	})
}

func testAccDataSourceAWSAuthBackendLoginConfig_iamIdentity(mountPath, accessKey, secretKey, reqMethod, reqURL, reqHeaders, reqBody, roleName, arn string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_client" "test" {
  backend = vault_auth_backend.aws.path
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_auth_backend_role" "test" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "iam"
  bound_iam_principal_arns = ["%s"]
  policies = ["default"]
  depends_on = ["vault_aws_auth_backend_client.test"]
}

resource "vault_aws_auth_backend_login" "test" {
  backend = vault_auth_backend.aws.path
  role = vault_aws_auth_backend_role.test.role
  iam_http_request_method = "%s"
  iam_request_url = "%s"
  iam_request_headers = "%s"
  iam_request_body = "%s"
}
`, mountPath, accessKey, secretKey, roleName, arn, reqMethod, reqURL, reqHeaders, reqBody)
}

func testAccDataSourceAWSAuthBackendLoginConfig_ec2Identity(mountPath, accessKey, secretKey, roleName, ami, account, arn, identity, signature string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_client" "test" {
  backend = vault_auth_backend.aws.path
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_auth_backend_role" "test" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "ec2"
  policies = ["default"]
  bound_ami_ids = ["%s"]
  bound_account_ids = ["%s"]
  bound_iam_instance_profile_arns = ["%s"]

  depends_on = ["vault_aws_auth_backend_client.test"]
}

resource "vault_aws_auth_backend_login" "test" {
  backend = vault_auth_backend.aws.path
  role = vault_aws_auth_backend_role.test.role
  identity = "%s"
  signature = "%s"
}
`, mountPath, accessKey, secretKey, roleName, ami, account, arn, identity, signature)
}

func testAccDataSourceAWSAuthBackendLoginConfig_pkcs7(mountPath, accessKey, secretKey, roleName, ami, account, arn, pkcs7 string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
}

resource "vault_aws_auth_backend_client" "test" {
  backend = vault_auth_backend.aws.path
  access_key = "%s"
  secret_key = "%s"
}

resource "vault_aws_auth_backend_role" "test" {
  backend = vault_auth_backend.aws.path
  role = "%s"
  auth_type = "ec2"
  policies = ["default"]
  bound_ami_ids = ["%s"]
  bound_account_ids = ["%s"]
  bound_iam_instance_profile_arns = ["%s"]

  depends_on = ["vault_aws_auth_backend_client.test"]
}

resource "vault_aws_auth_backend_login" "test" {
  backend = vault_auth_backend.aws.path
  role = vault_aws_auth_backend_role.test.role
  pkcs7 = "%s"
}
`, mountPath, accessKey, secretKey, roleName, ami, account, arn, pkcs7)
}
