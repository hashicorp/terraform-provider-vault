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

	// CHANGED: replaced session.NewSession(nil) with config.LoadDefaultConfig
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		t.Errorf("Error creating AWS config: %s", err)
	}

	// CHANGED: replaced sts.New(sess) with sts.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)

	// CHANGED: added context.TODO() as first argument
	testIdentity, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Errorf("Error obtaining identity document: %s", err)
	}

	// CHANGED: replaced GetCallerIdentityRequest (v1 presign pattern) with
	// v2 presign pattern using sts.NewPresignClient
	presignClient := sts.NewPresignClient(stsClient)
	presignedReq, err := presignClient.PresignGetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Errorf("Error presigning GetCallerIdentity request: %s", err)
	}

	reqMethod := "POST"
	reqURL := base64.StdEncoding.EncodeToString([]byte(presignedReq.URL))
	reqHeaders := base64.StdEncoding.EncodeToString([]byte("{}"))
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

	// CHANGED: replaced session.NewSession(nil) with config.LoadDefaultConfig
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		t.Errorf("Error creating AWS config: %s", err)
	}

	// CHANGED: replaced ec2metadata.New(sess) with imds.NewFromConfig(cfg)
	metadataClient := imds.NewFromConfig(cfg)

	// CHANGED: replaced metadata.Available() with GetInstanceIdentityDocument check
	_, err = metadataClient.GetInstanceIdentityDocument(context.TODO(), &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		t.Skip("Not running on EC2 instance, can't test ec2 auth methods.")
	}

	// CHANGED: replaced metadata.IAMInfo() with GetIAMInfo
	iamInfoOutput, err := metadataClient.GetIAMInfo(context.TODO(), &imds.GetIAMInfoInput{})
	if err != nil {
		t.Errorf("Error retrieving IAM info for instance: %s", err)
	}
	arn := iamInfoOutput.IAMInfo.InstanceProfileArn

	// CHANGED: replaced metadata.GetInstanceIdentityDocument() with v2 equivalent
	docOutput, err := metadataClient.GetInstanceIdentityDocument(context.TODO(), &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		t.Errorf("Error retrieving instance identity document: %s", err)
	}
	ami := docOutput.ImageID
	account := docOutput.AccountID

	// CHANGED: replaced metadata.GetDynamicData with GetDynamicData v2 pattern
	pkcs7Output, err := metadataClient.GetDynamicData(context.TODO(), &imds.GetDynamicDataInput{
		Path: "instance-identity/pkcs7",
	})
	if err != nil {
		t.Errorf("Error retrieving pkcs7 signature: %s", err)
	}
	// CHANGED: replaced ioutil.ReadAll with io.ReadAll
	pkcs7Bytes, err := io.ReadAll(pkcs7Output.Content)
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

	// CHANGED: replaced session.NewSession(nil) with config.LoadDefaultConfig
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		t.Errorf("Error creating AWS config: %s", err)
	}

	// CHANGED: replaced ec2metadata.New(sess) with imds.NewFromConfig(cfg)
	metadataClient := imds.NewFromConfig(cfg)

	// CHANGED: replaced metadata.Available() with GetInstanceIdentityDocument check
	_, err = metadataClient.GetInstanceIdentityDocument(context.TODO(), &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		t.Skip("Not running on EC2 instance, can't test ec2 auth methods.")
	}

	// CHANGED: replaced metadata.IAMInfo() with GetIAMInfo
	iamInfoOutput, err := metadataClient.GetIAMInfo(context.TODO(), &imds.GetIAMInfoInput{})
	if err != nil {
		t.Errorf("Error retrieving IAM info for instance: %s", err)
	}
	arn := iamInfoOutput.IAMInfo.InstanceProfileArn

	// CHANGED: replaced metadata.GetInstanceIdentityDocument() with v2 equivalent
	docOutput, err := metadataClient.GetInstanceIdentityDocument(context.TODO(), &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		t.Errorf("Error retrieving instance identity document: %s", err)
	}
	ami := docOutput.ImageID
	account := docOutput.AccountID

	// CHANGED: replaced metadata.GetDynamicData with v2 pattern
	identityOutput, err := metadataClient.GetDynamicData(context.TODO(), &imds.GetDynamicDataInput{
		Path: "instance-identity/document",
	})
	if err != nil {
		t.Errorf("Error retrieving raw identity: %s", err)
	}
	// CHANGED: replaced ioutil.ReadAll with io.ReadAll
	identityBytes, err := io.ReadAll(identityOutput.Content)
	if err != nil {
		t.Errorf("Error reading identity content: %s", err)
	}
	identity := base64.StdEncoding.EncodeToString(identityBytes)

	sigOutput, err := metadataClient.GetDynamicData(context.TODO(), &imds.GetDynamicDataInput{
		Path: "instance-identity/signature",
	})
	if err != nil {
		t.Errorf("Error retrieving signature: %s", err)
	}
	sigBytes, err := io.ReadAll(sigOutput.Content)
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
