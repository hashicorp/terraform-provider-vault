module github.com/hashicorp/terraform-provider-vault

go 1.21

require (
	cloud.google.com/go/compute/metadata v0.2.3
	cloud.google.com/go/iam v1.1.5
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.9.1
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.5.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.2.0
	github.com/aws/aws-sdk-go v1.49.22
	github.com/cenkalti/backoff/v4 v4.2.1
	github.com/coreos/pkg v0.0.0-20230601102743-20bbbf26f4d8
	github.com/denisenkom/go-mssqldb v0.12.3
	github.com/go-sql-driver/mysql v1.7.1
	github.com/google/uuid v1.5.0
	github.com/gosimple/slug v1.13.1
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-cty v1.4.1-0.20200723130312-85980079f637
	github.com/hashicorp/go-hclog v1.6.2
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.5
	github.com/hashicorp/go-secure-stdlib/awsutil v0.2.3
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.8
	github.com/hashicorp/go-version v1.6.0
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.31.0
	github.com/hashicorp/vault v1.11.3
	github.com/hashicorp/vault-plugin-auth-jwt v0.18.0
	github.com/hashicorp/vault-plugin-auth-kerberos v0.10.1
	github.com/hashicorp/vault-plugin-auth-oci v0.14.2
	github.com/hashicorp/vault/api v1.12.1-0.20240216201659-6dd2389edd36
	github.com/hashicorp/vault/sdk v0.10.2
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.5.0
	golang.org/x/crypto v0.18.0
	golang.org/x/net v0.20.0
	golang.org/x/oauth2 v0.16.0
	google.golang.org/api v0.156.0
	google.golang.org/genproto v0.0.0-20240116215550-a9fa1716bcac
	k8s.io/utils v0.0.0-20240102154912-e7106e64919e
)

require (
	cloud.google.com/go/compute v1.23.3 // indirect
	cloud.google.com/go/kms v1.15.5 // indirect
	cloud.google.com/go/monitoring v1.17.0 // indirect
	github.com/Azure/azure-sdk-for-go v61.4.0+incompatible // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.5.1 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.29 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.22 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.11 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.5 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.1 // indirect
	github.com/DataDog/datadog-go v3.2.0+incompatible // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.1 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20230828082145-3c4c8a2d2371 // indirect
	github.com/agext/levenshtein v1.2.2 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v0.0.0-20190620160927-9418d7b0cd0f // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/circonus-labs/circonus-gometrics v2.3.1+incompatible // indirect
	github.com/circonus-labs/circonusllhist v0.1.3 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/containerd/containerd v1.7.0 // indirect
	github.com/coreos/go-oidc/v3 v3.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/docker v24.0.7+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.4 // indirect
	github.com/go-jose/go-jose/v3 v3.0.1 // indirect
	github.com/go-ldap/ldap/v3 v3.4.4 // indirect
	github.com/go-logr/logr v1.3.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/go-metrics-stackdriver v0.2.0 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.0 // indirect
	github.com/gosimple/unidecode v1.0.1 // indirect
	github.com/hashicorp/cap v0.4.1 // indirect
	github.com/hashicorp/consul/api v1.14.0 // indirect
	github.com/hashicorp/go-checkpoint v0.5.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-kms-wrapping v0.7.0 // indirect
	github.com/hashicorp/go-kms-wrapping/entropy/v2 v2.0.0 // indirect
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.8 // indirect
	github.com/hashicorp/go-plugin v1.6.0 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2 // indirect
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.2 // indirect
	github.com/hashicorp/go-secure-stdlib/plugincontainer v0.2.2 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-secure-stdlib/tlsutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/hc-install v0.6.2 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/hashicorp/hcl/v2 v2.19.1 // indirect
	github.com/hashicorp/logutils v1.0.0 // indirect
	github.com/hashicorp/serf v0.9.7 // indirect
	github.com/hashicorp/terraform-exec v0.19.0 // indirect
	github.com/hashicorp/terraform-json v0.18.0 // indirect
	github.com/hashicorp/terraform-plugin-go v0.20.0 // indirect
	github.com/hashicorp/terraform-plugin-log v0.9.0 // indirect
	github.com/hashicorp/terraform-registry-address v0.2.3 // indirect
	github.com/hashicorp/terraform-svchost v0.1.1 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.16.5 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/cli v1.1.5 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/pointerstructure v1.2.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/patternmatcher v0.5.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/natefinch/atomic v0.0.0-20150920032501-a62ce929ffcc // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc2.0.20221005185240-3a7f492d3f1b // indirect
	github.com/opencontainers/runc v1.1.6 // indirect
	github.com/oracle/oci-go-sdk v24.3.0+incompatible // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/posener/complete v1.2.3 // indirect
	github.com/prometheus/client_golang v1.14.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/tv42/httpunix v0.0.0-20191220191345-2ba4b9c3382c // indirect
	github.com/vmihailenco/msgpack v4.0.4+incompatible // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/zclconf/go-cty v1.14.1 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.46.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.46.1 // indirect
	go.opentelemetry.io/otel v1.21.0 // indirect
	go.opentelemetry.io/otel/metric v1.21.0 // indirect
	go.opentelemetry.io/otel/trace v1.21.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.13.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240102182953-50ed04b92917 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240102182953-50ed04b92917 // indirect
	google.golang.org/grpc v1.60.1 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/jcmturner/goidentity.v3 v3.0.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
