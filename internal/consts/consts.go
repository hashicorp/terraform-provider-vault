package consts

const (
	/*
		common field names
	*/
	FieldPath                     = "path"
	FieldParameters               = "parameters"
	FieldMethod                   = "method"
	FieldNamespace                = "namespace"
	FieldNamespaceID              = "namespace_id"
	FieldBackend                  = "backend"
	FieldPathFQ                   = "path_fq"
	FieldData                     = "data"
	FieldMount                    = "mount"
	FieldName                     = "name"
	FieldVersion                  = "version"
	FieldMetadata                 = "metadata"
	FieldNames                    = "names"
	FieldLeaseID                  = "lease_id"
	FieldLeaseDuration            = "lease_duration"
	FieldLeaseRenewable           = "lease_renewable"
	FieldDepth                    = "depth"
	FieldDataJSON                 = "data_json"
	FieldRole                     = "role"
	FieldDescription              = "description"
	FieldTTL                      = "ttl"
	FieldDefaultLeaseTTL          = "default_lease_ttl_seconds"
	FieldMaxLeaseTTL              = "max_lease_ttl_seconds"
	FieldAuditNonHMACRequestKeys  = "audit_non_hmac_request_keys"
	FieldAuditNonHMACResponseKeys = "audit_non_hmac_response_keys"
	FieldLocal                    = "local"
	FieldSealWrap                 = "seal_wrap"
	FieldExternalEntropyAccess    = "external_entropy_access"
	FieldAWS                      = "aws"
	FieldPKCS                     = "pkcs"
	FieldAzure                    = "azure"
	FieldLibrary                  = "library"
	FieldKeyLabel                 = "key_label"
	FieldKeyID                    = "key_id"
	FieldMechanism                = "mechanism"
	FieldPin                      = "pin"
	FieldSlot                     = "slot"
	FieldTokenLabel               = "token_label"
	FieldCurve                    = "curve"
	FieldKeyBits                  = "key_bits"
	FieldForceRWSession           = "force_rw_session"
	FieldAWSAccessKey             = "access_key"
	FieldAWSSecretKey             = "secret_key"
	FieldEndpoint                 = "endpoint"
	FieldKeyType                  = "key_type"
	FieldKMSKey                   = "kms_key"
	FieldRegion                   = "region"
	FieldTenantID                 = "tenant_id"
	FieldClientID                 = "client_id"
	FieldClientSecret             = "client_secret"
	FieldEnvironment              = "environment"
	FieldVaultName                = "vault_name"
	FieldKeyName                  = "key_name"
	FieldResource                 = "resource"
	FieldAllowGenerateKey         = "allow_generate_key"
	FieldAllowReplaceKey          = "allow_replace_key"
	FieldAllowStoreKey            = "allow_store_key"
	FieldAnyMount                 = "any_mount"
	FieldUUID                     = "uuid"

	/*
		common environment variables
	*/
	EnvVarVaultNamespaceImport = "TERRAFORM_VAULT_NAMESPACE_IMPORT"
	EnvVarSkipChildToken       = "TERRAFORM_VAULT_SKIP_CHILD_TOKEN"

	/*
		common mount types
	*/
	MountTypeDatabase   = "database"
	MountTypePKI        = "pki"
	MountTypeAWS        = "aws"
	MountTypeKMIP       = "kmip"
	MountTypeRabbitMQ   = "rabbitmq"
	MountTypeNomad      = "nomad"
	MountTypeKubernetes = "kubernetes"

	/*
		misc. path related constants
	*/
	PathDelim = "/"
)
