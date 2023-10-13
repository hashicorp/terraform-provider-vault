module github.com/hashicorp/terraform-provider-vault

go 1.16

require (
	cloud.google.com/go/compute/metadata v0.2.3
	cloud.google.com/go/iam v1.1.2
	github.com/Azure/azure-sdk-for-go/sdk/azcore v0.22.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v0.13.2
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v0.3.1
	github.com/Azure/go-autorest/autorest v0.11.29
	github.com/aws/aws-sdk-go v1.45.24
	github.com/cenkalti/backoff/v4 v4.2.1
	github.com/coreos/pkg v0.0.0-20230601102743-20bbbf26f4d8
	github.com/denisenkom/go-mssqldb v0.12.3
	github.com/go-sql-driver/mysql v1.7.1
	github.com/google/uuid v1.3.1
	github.com/gosimple/slug v1.13.1
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-cty v1.4.1-0.20200723130312-85980079f637
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.4
	github.com/hashicorp/go-secure-stdlib/awsutil v0.2.3
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7
	github.com/hashicorp/go-version v1.6.0
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.29.0
	github.com/hashicorp/vault v1.11.3
	github.com/hashicorp/vault-plugin-auth-jwt v0.17.0
	github.com/hashicorp/vault-plugin-auth-kerberos v0.10.1
	github.com/hashicorp/vault-plugin-auth-oci v0.14.2
	github.com/hashicorp/vault/api v1.10.0
	github.com/hashicorp/vault/sdk v0.10.0
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.5.0
	go.uber.org/atomic v1.10.0 // indirect
	golang.org/x/crypto v0.14.0
	golang.org/x/net v0.15.0
	golang.org/x/oauth2 v0.12.0
	google.golang.org/api v0.144.0
	google.golang.org/genproto v0.0.0-20231002182017-d307bd883b97
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b
)
