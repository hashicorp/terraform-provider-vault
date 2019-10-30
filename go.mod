module github.com/terraform-providers/terraform-provider-vault

go 1.12

require (
	github.com/aws/aws-sdk-go v1.22.0
	github.com/go-sql-driver/mysql v1.4.1
	github.com/google/btree v1.0.0 // indirect
	github.com/gosimple/slug v1.4.1
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/terraform-plugin-sdk v1.1.1
	github.com/hashicorp/vault v1.2.0
	github.com/hashicorp/vault/api v1.0.5-0.20190730042357-746c0b111519
	github.com/hashicorp/vault/sdk v0.1.14-0.20190730042320-0dc007d98cc8
	github.com/mitchellh/go-homedir v1.1.0
	github.com/ory/dockertest v3.3.4+incompatible
	github.com/rainycape/unidecode v0.0.0-20150907023854-cb7f23ec59be // indirect
	github.com/ulikunitz/xz v0.5.6 // indirect
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0
