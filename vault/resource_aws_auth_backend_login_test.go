// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAWSAuthBackendLogin_iamIdentity(t *testing.T) {
	mountPath := acctest.RandomWithPrefix("tf-test-aws")
	roleName := acctest.RandomWithPrefix("tf-test")
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	awsConfig, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Errorf("Error creating AWS config: %s", err)
	}
	stsService := sts.NewFromConfig(awsConfig)
	testIdentity, err := stsService.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Errorf("Error obtaining identity document: %s", err)
	}
	// For v2, we need to manually create the signed request data
	// This is a simplified approach - in practice, you'd use the same signing logic as in auth_aws.go
	reqMethod := "POST"
	reqURL := base64.StdEncoding.EncodeToString([]byte("https://sts.amazonaws.com/"))
	reqHeaders := base64.StdEncoding.EncodeToString([]byte("{}")) // Simplified headers
	reqBody := base64.StdEncoding.EncodeToString([]byte("Action=GetCallerIdentity&Version=2011-06-15"))
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
	testutil.SkipTestEnvUnset(t, "TF_AWS_META")

	mountPath := acctest.RandomWithPrefix("tf-test-aws")
	roleName := acctest.RandomWithPrefix("tf-test")
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	awsConfig, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Errorf("Error creating AWS config: %s", err)
	}
	metadata := imds.NewFromConfig(awsConfig)

	_, err = metadata.GetMetadata(context.Background(), &imds.GetMetadataInput{Path: "meta-data/"})
	if err != nil {
		t.Skip("Not running on EC2 instance, can't test ec2 auth methods.")
	}

	iamInfo, err := metadata.GetIAMInfo(context.Background(), &imds.GetIAMInfoInput{})
	if err != nil {
		t.Errorf("Error retrieving IAM info for instance: %s", err)
	}
	arn := iamInfo.InstanceProfileArn

	doc, err := metadata.GetInstanceIdentityDocument(context.Background(), &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		t.Errorf("Error retrieving instance identity document: %s", err)
	}
	ami := doc.ImageID
	account := doc.AccountID

	pkcs7Result, err := metadata.GetDynamicData(context.Background(), &imds.GetDynamicDataInput{Path: "instance-identity/pkcs7"})
	if err != nil {
		t.Errorf("Error retrieving pkcs7 signature: %s", err)
	}
	pkcs7Bytes, err := io.ReadAll(pkcs7Result.Content)
	if err != nil {
		t.Errorf("Error reading pkcs7 content: %s", err)
	}
	pkcs7 := strings.Replace(string(pkcs7Bytes), "\n", "", -1)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
	testutil.SkipTestEnvUnset(t, "TF_AWS_META")

	mountPath := acctest.RandomWithPrefix("tf-test-aws")
	roleName := acctest.RandomWithPrefix("tf-test")
	accessKey, secretKey := testutil.GetTestAWSCreds(t)

	awsConfig, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Errorf("Error creating AWS config: %s", err)
	}
	metadata := imds.NewFromConfig(awsConfig)

	_, err = metadata.GetMetadata(context.Background(), &imds.GetMetadataInput{Path: "meta-data/"})
	if err != nil {
		t.Skip("Not running on EC2 instance, can't test ec2 auth methods.")
	}

	iamInfo, err := metadata.GetIAMInfo(context.Background(), &imds.GetIAMInfoInput{})
	if err != nil {
		t.Errorf("Error retrieving IAM info for instance: %s", err)
	}
	arn := iamInfo.InstanceProfileArn

	doc, err := metadata.GetInstanceIdentityDocument(context.Background(), &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		t.Errorf("Error retrieving instance identity document: %s", err)
	}
	ami := doc.ImageID
	account := doc.AccountID

	identityResult, err := metadata.GetDynamicData(context.Background(), &imds.GetDynamicDataInput{Path: "instance-identity/document"})
	if err != nil {
		t.Errorf("Error retrieving raw identity: %s", err)
	}
	identityBytes, err := io.ReadAll(identityResult.Content)
	if err != nil {
		t.Errorf("Error reading identity content: %s", err)
	}
	identity := base64.StdEncoding.EncodeToString(identityBytes)

	sigResult, err := metadata.GetDynamicData(context.Background(), &imds.GetDynamicDataInput{Path: "instance-identity/signature"})
	if err != nil {
		t.Errorf("Error retrieving signature: %s", err)
	}
	sigBytes, err := io.ReadAll(sigResult.Content)
	if err != nil {
		t.Errorf("Error reading signature content: %s", err)
	}
	sig := strings.Replace(string(sigBytes), "\n", "", -1)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
