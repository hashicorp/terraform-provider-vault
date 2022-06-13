package consts

const (
	/*
		common field names
	*/
	FieldPath           = "path"
	FieldParameters     = "parameters"
	FieldMethod         = "method"
	FieldNamespace      = "namespace"
	FieldNamespaceID    = "namespace_id"
	FieldBackend        = "backend"
	FieldData           = "data"
	FieldMount          = "mount"
	FieldName           = "name"
	FieldVersion        = "version"
	FieldMetadata       = "metadata"
	FieldNames          = "names"
	FieldLeaseID        = "lease_id"
	FieldLeaseDuration  = "lease_duration"
	FieldLeaseRenewable = "lease_renewable"
	/*
		common environment variables
	*/
	EnvVarVaultNamespaceImport = "TERRAFORM_VAULT_NAMESPACE_IMPORT"
	EnvVarSkipChildToken       = "TERRAFORM_VAULT_SKIP_CHILD_TOKEN"

	/*
		common mount types
	*/
	MountTypeDatabase = "database"
	MountTypePKI      = "pki"
	MountTypeAWS      = "aws"
	MountTypeKMIP     = "kmip"
	MountTypeRabbitMQ = "rabbitmq"
	MountTypeNomad    = "nomad"

	/*
		misc. path related constants
	*/
	PathDelim = "/"
)
