package consts

const (
	// common field names
	FieldPath       = "path"
	FieldParameters = "parameters"
	FieldMethod     = "method"
	FieldNamespace  = "namespace"
	FieldBackend    = "backend"

	// env vars
	EnvVarVaultNamespaceImport = "TERRAFORM_VAULT_NAMESPACE_IMPORT"
	EnvVarSkipChildToken       = "TERRAFORM_VAULT_SKIP_CHILD_TOKEN"

	// common mount types
	MountTypeDatabase = "database"
	MountTypePKI      = "pki"
	MountTypeAWS      = "aws"
	MountTypeKMIP     = "kmip"
	MountTypeRabbitMQ = "rabbitmq"
	MountTypeNomad    = "nomad"
)
