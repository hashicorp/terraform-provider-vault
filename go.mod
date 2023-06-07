module github.com/hashicorp/terraform-provider-vault

go 1.16

require (
	cloud.google.com/go/compute/metadata v0.2.3
	cloud.google.com/go/iam v0.12.0
	github.com/Azure/azure-sdk-for-go/sdk/azcore v0.22.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v0.13.2
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v0.3.1
	github.com/Azure/go-autorest/autorest v0.11.24
	github.com/aws/aws-sdk-go v1.44.106
	github.com/cenkalti/backoff/v4 v4.2.0
	github.com/coreos/go-oidc/v3 v3.4.0 // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f
	github.com/denisenkom/go-mssqldb v0.12.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gosimple/slug v1.11.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-cty v1.4.1-0.20200414143053-d3edf31b6320
	github.com/hashicorp/go-hclog v1.4.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.1
	github.com/hashicorp/go-secure-stdlib/awsutil v0.1.6
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7
	github.com/hashicorp/go-version v1.6.0
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.16.0
	github.com/hashicorp/vault v1.11.3
	github.com/hashicorp/vault-plugin-auth-jwt v0.13.2-0.20221012184020-28cc68ee722b
	github.com/hashicorp/vault-plugin-auth-kerberos v0.8.0
	github.com/hashicorp/vault-plugin-auth-oci v0.13.0-pre
	github.com/hashicorp/vault/api v1.9.2
	github.com/hashicorp/vault/sdk v0.9.1
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.2
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/mitchellh/pointerstructure v1.2.1 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	golang.org/x/crypto v0.6.0
	golang.org/x/net v0.8.0
	golang.org/x/oauth2 v0.5.0
	google.golang.org/api v0.110.0
	google.golang.org/genproto v0.0.0-20230306155012-7f2fa6fef1f4
	k8s.io/utils v0.0.0-20230220204549-a5ecb0141aa5
)
