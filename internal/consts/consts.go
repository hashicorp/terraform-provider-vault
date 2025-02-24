// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package consts

const (
	/*
		common field names
	*/
	// FieldBackend
	// Deprecated: Prefer FieldMount or FieldPath instead.
	FieldBackend = "backend"
	// FieldPath should be used for all new backend-mounting resources.
	FieldPath = "path"
	// FieldMount should be used for all new non-backend-mounting resources.
	// In other words, resources that depend on a backend-mounting resource should use this.
	FieldMount                         = "mount"
	FieldBindDN                        = "binddn"
	FieldBindPass                      = "bindpass"
	FieldCertificate                   = "certificate"
	FieldClientTLSCert                 = "client_tls_cert"
	FieldClientTLSKey                  = "client_tls_key"
	FieldDistinguishedNames            = "distinguished_names"
	FieldUPNDomain                     = "upndomain"
	FieldStartTLS                      = "starttls"
	FieldConnectionTimeout             = "connection_timeout"
	FieldRequestTimeout                = "request_timeout"
	FieldSchema                        = "schema"
	FieldPasswordPolicy                = "password_policy"
	FieldLength                        = "length"
	FieldInsecureTLS                   = "insecure_tls"
	FieldURL                           = "url"
	FieldUserAttr                      = "userattr"
	FieldUserDN                        = "userdn"
	FieldRotationPeriod                = "rotation_period"
	FieldPaths                         = "paths"
	FieldParameters                    = "parameters"
	FieldMethod                        = "method"
	FieldNamespace                     = "namespace"
	FieldUseRootNamespace              = "use_root_namespace"
	FieldNamespaceID                   = "namespace_id"
	FieldNamespacePath                 = "namespace_path"
	FieldPathFQ                        = "path_fq"
	FieldData                          = "data"
	FieldDisableRead                   = "disable_read"
	FieldName                          = "name"
	FieldVersion                       = "version"
	FieldMetadata                      = "metadata"
	FieldNames                         = "names"
	FieldLeaseID                       = "lease_id"
	FieldLeaseDuration                 = "lease_duration"
	FieldLeaseRenewable                = "lease_renewable"
	FieldDepth                         = "depth"
	FieldDataJSON                      = "data_json"
	FieldDN                            = "dn"
	FieldRole                          = "role"
	FieldRoles                         = "roles"
	FieldDescription                   = "description"
	FieldTTL                           = "ttl"
	FieldMaxTTL                        = "max_ttl"
	FieldDefaultLeaseTTL               = "default_lease_ttl_seconds"
	FieldDefaultTTL                    = "default_ttl"
	FieldMaxLeaseTTL                   = "max_lease_ttl_seconds"
	FieldAuditNonHMACRequestKeys       = "audit_non_hmac_request_keys"
	FieldAuditNonHMACResponseKeys      = "audit_non_hmac_response_keys"
	FieldLastPassword                  = "last_password"
	FieldLastVaultRotation             = "last_vault_rotation"
	FieldLocal                         = "local"
	FieldSealWrap                      = "seal_wrap"
	FieldExternalEntropyAccess         = "external_entropy_access"
	FieldAWS                           = "aws"
	FieldPKCS                          = "pkcs"
	FieldAzure                         = "azure"
	FieldLibrary                       = "library"
	FieldKeyLabel                      = "key_label"
	FieldKeyID                         = "key_id"
	FieldMechanism                     = "mechanism"
	FieldPin                           = "pin"
	FieldSlot                          = "slot"
	FieldTokenLabel                    = "token_label"
	FieldCurve                         = "curve"
	FieldKeyBits                       = "key_bits"
	FieldSignatureBits                 = "signature_bits"
	FieldForceRWSession                = "force_rw_session"
	FieldAccessKey                     = "access_key"
	FieldSecretKey                     = "secret_key"
	FieldEndpoint                      = "endpoint"
	FieldKeyType                       = "key_type"
	FieldKMSKey                        = "kms_key"
	FieldRegion                        = "region"
	FieldTenantID                      = "tenant_id"
	FieldClientID                      = "client_id"
	FieldClientSecret                  = "client_secret"
	FieldEnvironment                   = "environment"
	FieldVaultName                     = "vault_name"
	FieldKeyName                       = "key_name"
	FieldResource                      = "resource"
	FieldAllowGenerateKey              = "allow_generate_key"
	FieldAllowReplaceKey               = "allow_replace_key"
	FieldAllowStoreKey                 = "allow_store_key"
	FieldAnyMount                      = "any_mount"
	FieldID                            = "id"
	FieldUUID                          = "uuid"
	FieldMountAccessor                 = "mount_accessor"
	FieldUsername                      = "username"
	FieldPassword                      = "password"
	FieldPasswordFile                  = "password_file"
	FieldClientAuth                    = "client_auth"
	FieldAuthLoginGeneric              = "auth_login"
	FieldAuthLoginUserpass             = "auth_login_userpass"
	FieldAuthLoginAWS                  = "auth_login_aws"
	FieldAuthLoginCert                 = "auth_login_cert"
	FieldAuthLoginGCP                  = "auth_login_gcp"
	FieldAuthLoginKerberos             = "auth_login_kerberos"
	FieldAuthLoginRadius               = "auth_login_radius"
	FieldAuthLoginOCI                  = "auth_login_oci"
	FieldAuthLoginOIDC                 = "auth_login_oidc"
	FieldAuthLoginJWT                  = "auth_login_jwt"
	FieldAuthLoginAzure                = "auth_login_azure"
	FieldAuthLoginTokenFile            = "auth_login_token_file"
	FieldIAMHttpRequestMethod          = "iam_http_request_method"
	FieldIAMRequestURL                 = "iam_request_url"
	FieldIAMRequestBody                = "iam_request_body"
	FieldIAMRequestHeaders             = "iam_request_headers"
	FieldAWSAccessKeyID                = "aws_access_key_id"
	FieldAWSSecretAccessKey            = "aws_secret_access_key"
	FieldAWSSessionToken               = "aws_session_token"
	FieldAWSRoleARN                    = "aws_role_arn"
	FieldAWSRoleSessionName            = "aws_role_session_name"
	FieldAWSWebIdentityTokenFile       = "aws_web_identity_token_file"
	FieldAWSSTSEndpoint                = "aws_sts_endpoint"
	FieldAWSIAMEndpoint                = "aws_iam_endpoint"
	FieldAWSProfile                    = "aws_profile"
	FieldAWSRegion                     = "aws_region"
	FieldAWSSharedCredentialsFile      = "aws_shared_credentials_file"
	FieldHeaderValue                   = "header_value"
	FieldDisableRemount                = "disable_remount"
	FieldCACertFile                    = "ca_cert_file"
	FieldCACertDir                     = "ca_cert_dir"
	FieldCertFile                      = "cert_file"
	FieldKeyFile                       = "key_file"
	FieldSkipTLSVerify                 = "skip_tls_verify"
	FieldTLSServerName                 = "tls_server_name"
	FieldAddress                       = "address"
	FieldJWT                           = "jwt"
	FieldCredentials                   = "credentials"
	FieldClientEmail                   = "client_email"
	FieldServiceAccount                = "service_account"
	FieldAuthorization                 = "authorization"
	FieldToken                         = "token"
	FieldService                       = "service"
	FieldRealm                         = "realm"
	FieldKeytabPath                    = "keytab_path"
	FieldKRB5ConfPath                  = "krb5conf_path"
	FieldDisableFastNegotiation        = "disable_fast_negotiation"
	FieldRemoveInstanceName            = "remove_instance_name"
	FieldAuthType                      = "auth_type"
	FieldRequestHeaders                = "request_headers"
	FieldCallbackAddress               = "callback_address"
	FieldCallbackListenerAddress       = "callback_listener_address"
	FieldScope                         = "scope"
	FieldSubscriptionID                = "subscription_id"
	FieldResourceGroupName             = "resource_group_name"
	FieldVMName                        = "vm_name"
	FieldVMSSName                      = "vmss_name"
	FieldUsernameFormat                = "username_format"
	FieldIntegrationKey                = "integration_key"
	FieldAPIHostname                   = "api_hostname"
	FieldPushInfo                      = "push_info"
	FieldUsePasscode                   = "use_passcode"
	FieldIssuer                        = "issuer"
	FieldPeriod                        = "period"
	FieldKeySize                       = "key_size"
	FieldQRSize                        = "qr_size"
	FieldAlgorithm                     = "algorithm"
	FieldDigits                        = "digits"
	FieldSkew                          = "skew"
	FieldMaxValidationAttempts         = "max_validation_attempts"
	FieldOrgName                       = "org_name"
	FieldAPIToken                      = "api_token"
	FieldBaseURL                       = "base_url"
	FieldPrimaryEmail                  = "primary_email"
	FieldSettingsFileBase64            = "settings_file_base64"
	FieldUseSignature                  = "use_signature"
	FieldIdpURL                        = "idp_url"
	FieldAdminURL                      = "admin_url"
	FieldAuthenticatorURL              = "authenticator_url"
	FieldOrgAlias                      = "org_alias"
	FieldType                          = "type"
	FieldMethodID                      = "method_id"
	FieldMFAMethodIDs                  = "mfa_method_ids"
	FieldAccessors                     = "accessors"
	FieldAuthMethodAccessors           = "auth_method_accessors"
	FieldAuthMethodTypes               = "auth_method_types"
	FieldIdentityGroupIDs              = "identity_group_ids"
	FieldIdentityEntityIDs             = "identity_entity_ids"
	FieldWrappingAccessor              = "wrapping_accessor"
	FieldRoleName                      = "role_name"
	FieldPolicies                      = "policies"
	FieldNoParent                      = "no_parent"
	FieldNoDefaultPolicy               = "no_default_policy"
	FieldRenewable                     = "renewable"
	FieldExplicitMaxTTL                = "explicit_max_ttl"
	FieldWrappingTTL                   = "wrapping_ttl"
	FieldDisplayName                   = "display_name"
	FieldNumUses                       = "num_uses"
	FieldRenewMinLease                 = "renew_min_lease"
	FieldRenewIncrement                = "renew_increment"
	FieldLeaseStarted                  = "lease_started"
	FieldClientToken                   = "client_token"
	FieldWrappedToken                  = "wrapped_token"
	FieldOrphan                        = "orphan"
	FieldVaultVersionOverride          = "vault_version_override"
	FieldSkipGetVaultVersion           = "skip_get_vault_version"
	FieldMemberEntityIDs               = "member_entity_ids"
	FieldMemberGroupIDs                = "member_group_ids"
	FieldExclusive                     = "exclusive"
	FieldGroupID                       = "group_id"
	FieldGroupName                     = "group_name"
	FieldExternal                      = "external"
	FieldInternal                      = "internal"
	FieldFailureTolerance              = "failure_tolerance"
	FieldHealthy                       = "healthy"
	FieldLeader                        = "leader"
	FieldOptimisticFailureTolerance    = "optimistic_failure_tolerance"
	FieldVoters                        = "voters"
	FieldRedundancyZones               = "redundancy_zones"
	FieldRedundancyZonesJSON           = "redundancy_zones_json"
	FieldServers                       = "servers"
	FieldServersJSON                   = "servers_json"
	FieldUpgradeInfo                   = "upgrade_info"
	FieldUpgradeInfoJSON               = "upgrade_info_json"
	FieldMaxVersions                   = "max_versions"
	FieldCASRequired                   = "cas_required"
	FieldDeleteVersionAfter            = "delete_version_after"
	FieldCustomMetadata                = "custom_metadata"
	FieldCustomMetadataJSON            = "custom_metadata_json"
	FieldIAMAlias                      = "iam_alias"
	FieldIAMMetadata                   = "iam_metadata"
	FieldEC2Alias                      = "ec2_alias"
	FieldEC2Metadata                   = "ec2_metadata"
	FieldPublicKey                     = "public_key"
	FieldPrivateKey                    = "private_key"
	FieldImpersonatedAccount           = "impersonated_account"
	FieldServiceAccountEmail           = "service_account_email"
	FieldTokenScopes                   = "token_scopes"
	FieldServiceAccountProject         = "service_account_project"
	FieldOrganizationID                = "organization_id"
	FieldProjectID                     = "project_id"
	FieldIPAddresses                   = "ip_addresses"
	FieldCIDRBlocks                    = "cidr_blocks"
	FieldProjectRoles                  = "project_roles"
	FieldCreationLDIF                  = "creation_ldif"
	FieldDeletionLDIF                  = "deletion_ldif"
	FieldRollbackLDIF                  = "rollback_ldif"
	FieldUsernameTemplate              = "username_template"
	FieldServiceAccountNames           = "service_account_names"
	FieldDisableCheckInEnforcement     = "disable_check_in_enforcement"
	FieldSkipChildToken                = "skip_child_token"
	FieldTokenPolicies                 = "token_policies"
	FieldManagedKeyName                = "managed_key_name"
	FieldManagedKeyID                  = "managed_key_id"
	FieldIssuerRef                     = "issuer_ref"
	FieldAllowLocalhost                = "allow_localhost"
	FieldAllowedDomains                = "allowed_domains"
	FieldAllowedDomainsTemplate        = "allowed_domains_template"
	FieldAllowBareDomains              = "allow_bare_domains"
	FieldAllowSubdomains               = "allow_subdomains"
	FieldAllowGlobDomains              = "allow_glob_domains"
	FieldAllowAnyName                  = "allow_any_name"
	FieldEnforceHostnames              = "enforce_hostnames"
	FieldAllowIPSans                   = "allow_ip_sans"
	FieldAllowedURISans                = "allowed_uri_sans"
	FieldAllowedURISansTemplate        = "allowed_uri_sans_template"
	FieldAllowedUserIds                = "allowed_user_ids"
	FieldAllowWildcardCertificates     = "allow_wildcard_certificates"
	FieldAllowedOtherSans              = "allowed_other_sans"
	FieldServerFlag                    = "server_flag"
	FieldClientFlag                    = "client_flag"
	FieldCodeSigningFlag               = "code_signing_flag"
	FieldEmailProtectionFlag           = "email_protection_flag"
	FieldKeyUsage                      = "key_usage"
	FieldExtKeyUsage                   = "ext_key_usage"
	FieldExtKeyUsageOIDs               = "ext_key_usage_oids"
	FieldUseCSRCommonName              = "use_csr_common_name"
	FieldUseCSRSans                    = "use_csr_sans"
	FieldOU                            = "ou"
	FieldOrganization                  = "organization"
	FieldCountry                       = "country"
	FieldLocality                      = "locality"
	FieldProvince                      = "province"
	FieldStreetAddress                 = "street_address"
	FieldPostalCode                    = "postal_code"
	FieldGenerateLease                 = "generate_lease"
	FieldNoStore                       = "no_store"
	FieldRequireCN                     = "require_cn"
	FieldPolicyIdentifiers             = "policy_identifiers"
	FieldPolicyIdentifier              = "policy_identifier"
	FieldBasicConstraintsValidForNonCA = "basic_constraints_valid_for_non_ca"
	FieldNotBeforeDuration             = "not_before_duration"
	FieldAllowedSerialNumbers          = "allowed_serial_numbers"
	FieldOID                           = "oid"
	FieldCPS                           = "cps"
	FieldNotice                        = "notice"
	FieldCommonName                    = "common_name"
	FieldAltNames                      = "alt_names"
	FieldFormat                        = "format"
	FieldPrivateKeyFormat              = "private_key_format"
	FieldOu                            = "ou"
	FieldIssuingCA                     = "issuing_ca"
	FieldSerial                        = "serial"
	FieldSerialNumber                  = "serial_number"
	FieldIPSans                        = "ip_sans"
	FieldURISans                       = "uri_sans"
	FieldOtherSans                     = "other_sans"
	FieldMaxPathLength                 = "max_path_length"
	FieldExcludeCNFromSans             = "exclude_cn_from_sans"
	FieldPermittedDNSDomains           = "permitted_dns_domains"
	FieldExcludedDNSDomains            = "excluded_dns_domains"
	FieldPermittedIPRanges             = "permitted_ip_ranges"
	FieldExcludedIPRanges              = "excluded_ip_ranges"
	FieldPermittedEmailAddresses       = "permitted_email_addresses"
	FieldExcludedEmailAddresses        = "excluded_email_addresses"
	FieldPermittedURIDomains           = "permitted_uri_domains"
	FieldExcludedURIDomains            = "excluded_uri_domains"
	FieldIssuerName                    = "issuer_name"
	FieldUserIds                       = "user_ids"
	FieldIssuerID                      = "issuer_id"
	FieldKeyRef                        = "key_ref"
	FieldPemBundle                     = "pem_bundle"
	FieldCAChain                       = "ca_chain"
	FieldCSR                           = "csr"
	FieldUseCSRValues                  = "use_csr_values"
	FieldCertificateBundle             = "certificate_bundle"
	FieldRevoke                        = "revoke"
	FieldRevokeWithKey                 = "revoke_with_key"
	FieldPrivateKeyType                = "private_key_type"
	FieldAddBasicConstraints           = "add_basic_constraints"
	FieldExported                      = "exported"
	FieldExpiration                    = "expiration"
	FieldAutoRenew                     = "auto_renew"
	FieldMinSecondsRemaining           = "min_seconds_remaining"
	FieldRenewPending                  = "renew_pending"
	FieldImportedIssuers               = "imported_issuers"
	FieldImportedKeys                  = "imported_keys"
	FieldExisting                      = "existing"
	FieldLeafNotAfterBehavior          = "leaf_not_after_behavior"
	FieldManualChain                   = "manual_chain"
	FieldUsage                         = "usage"
	FieldKeys                          = "keys"
	FieldKeyInfo                       = "key_info"
	FieldKeyInfoJSON                   = "key_info_json"
	FieldRevocationSignatureAlgorithm  = "revocation_signature_algorithm"
	FieldIssuingCertificates           = "issuing_certificates"
	FieldCRLDistributionPoints         = "crl_distribution_points"
	FieldOCSPServers                   = "ocsp_servers"
	FieldEnableAIAURLTemplating        = "enable_aia_url_templating"
	FieldCredentialConfig              = "credential_config"
	FieldDBName                        = "db_name"
	FieldCreationStatements            = "creation_statements"
	FieldRevocationStatements          = "revocation_statements"
	FieldRollbackStatements            = "rollback_statements"
	FieldRenewStatements               = "renew_statements"
	FieldCredentialType                = "credential_type"
	FieldFilename                      = "filename"
	FieldDefault                       = "default"
	FieldRotationStatements            = "rotation_statements"
	FieldRotationSchedule              = "rotation_schedule"
	FieldRotationWindow                = "rotation_window"
	FieldKubernetesCACert              = "kubernetes_ca_cert"
	FieldDisableLocalCAJWT             = "disable_local_ca_jwt"
	FieldKubernetesHost                = "kubernetes_host"
	FieldServiceAccountJWT             = "service_account_jwt"
	FieldDisableISSValidation          = "disable_iss_validation"
	FieldPEMKeys                       = "pem_keys"
	FieldSetNamespaceFromToken         = "set_namespace_from_token"
	FieldAzureRoles                    = "azure_roles"
	FieldRoleID                        = "role_id"
	FieldAzureGroups                   = "azure_groups"
	FieldObjectID                      = "object_id"
	FieldApplicationObjectID           = "application_object_id"
	FieldPermanentlyDelete             = "permanently_delete"
	FieldSignInAudience                = "sign_in_audience"
	FieldTags                          = "tags"
	FieldSkipStaticRoleImportRotation  = "skip_static_role_import_rotation"
	FieldSkipImportRotation            = "skip_import_rotation"
	FieldCustomTags                    = "custom_tags"
	FieldSecretNameTemplate            = "secret_name_template"
	FieldIAMEndpoint                   = "iam_endpoint"
	FieldSTSEndpoint                   = "sts_endpoint"
	FieldSTSFallbackEndpoints          = "sts_fallback_endpoints"
	FieldIdentityTokenAudience         = "identity_token_audience"
	FieldIdentityTokenTTL              = "identity_token_ttl"
	FieldRoleArn                       = "role_arn"
	FieldAccessor                      = "accessor"
	FieldOptions                       = "options"
	FieldAllowedManagedKeys            = "allowed_managed_keys"
	FieldIdentityTokenKey              = "identity_token_key"
	FieldCIDRList                      = "cidr_list"
	FieldSecretID                      = "secret_id"
	FieldWrappingToken                 = "wrapping_token"
	FieldWithWrappedAccessor           = "with_wrapped_accessor"
	FieldExternalID                    = "external_id"
	FieldAppName                       = "app_name"
	FieldInstallationID                = "installation_id"
	FieldAppID                         = "app_id"
	FieldAIAPath                       = "aia_path"
	FieldTLSMinVersion                 = "tls_min_version"
	FieldTLSMaxVersion                 = "tls_max_version"
	FieldCaseSensitiveNames            = "case_sensitive_names"
	FieldMaxPageSize                   = "max_page_size"
	FieldUserFilter                    = "userfilter"
	FieldDiscoverDN                    = "discoverdn"
	FieldDenyNullBind                  = "deny_null_bind"
	FieldGroupFilter                   = "groupfilter"
	FieldGroupDN                       = "groupdn"
	FieldGroupAttr                     = "groupattr"
	FieldUsernameAsAlias               = "username_as_alias"
	FieldUseTokenGroups                = "use_token_groups"
	FieldTitle                         = "title"
	FieldMessageBase64                 = "message_base64"
	FieldAuthenticated                 = "authenticated"
	FieldStartTime                     = "start_time"
	FieldEndTime                       = "end_time"
	FieldLink                          = "link"
	FieldGranularity                   = "granularity"
	FieldGranularityLevel              = "granularity_level"
	FieldEC2Endpoint                   = "ec2_endpoint"
	FieldSTSRegion                     = "sts_region"
	FieldSTSFallbackRegions            = "sts_fallback_regions"
	FieldIAMServerIDHeaderValue        = "iam_server_id_header_value"
	FieldListingVisibility             = "listing_visibility"
	FieldPassthroughRequestHeaders     = "passthrough_request_headers"
	FieldAllowedResponseHeaders        = "allowed_response_headers"
	FieldDelegatedAuthAccessors        = "delegated_auth_accessors"
	FieldPluginVersion                 = "plugin_version"
	FieldUseMSGraphAPI                 = "use_microsoft_graph_api"
	FieldEnabled                       = "enabled"
	FieldDefaultMount                  = "default_mount"
	FieldDefaultPathPolicy             = "default_path_policy"
	FieldLabelToPathPolicy             = "label_to_path_policy"
	FieldAuthenticators                = "authenticators"
	FieldEnableSentinelParsing         = "enable_sentinel_parsing"
	FieldAuditFields                   = "audit_fields"
	FieldLastUpdated                   = "last_updated"
	FieldCustomEndpoint                = "custom_endpoint"
	FieldPrivateKeyID                  = "private_key_id"
	FieldTune                          = "tune"
	FieldMaxRetries                    = "max_retries"
	FieldSessionTags                   = "session_tags"
	FieldSelfManagedPassword           = "self_managed_password"
	FieldAllowedIssuers                = "allowed_issuers"
	FieldAllowedRoles                  = "allowed_roles"
	FieldAllowRoleExtKeyUsage          = "allow_role_ext_key_usage"
	FieldDefaultDirectoryPolicy        = "default_directory_policy"
	FieldDnsResolver                   = "dns_resolver"
	FieldEabPolicy                     = "eab_policy"
	FieldCnValidations                 = "cn_validations"
	FieldsCreatedOn                    = "created_on"
	FieldEabKey                        = "key"
	FieldAcmeDirectory                 = "acme_directory"
	FieldEabId                         = "eab_id"
	FieldAssumeRoleArn                 = "assume_role_arn"
	FieldAssumeRoleSessionName         = "assume_role_session_name"

	FieldDisableCriticalExtensionChecks = "disable_critical_extension_checks"
	FieldDisablePathLengthChecks        = "disable_path_length_checks"
	FieldDisableNameChecks              = "disable_name_checks"
	FieldDisableNameConstraintChecks    = "disable_name_constraint_checks"

	/*
		common environment variables
	*/
	EnvVarVaultNamespaceImport = "TERRAFORM_VAULT_NAMESPACE_IMPORT"
	EnvVarSkipChildToken       = "TERRAFORM_VAULT_SKIP_CHILD_TOKEN"
	// EnvVarUsername to get the username for the userpass auth method
	EnvVarUsername = "TERRAFORM_VAULT_USERNAME"
	// EnvVarPassword to get the password for the userpass auth method
	EnvVarPassword = "TERRAFORM_VAULT_PASSWORD"
	// EnvVarPasswordFile to get the password for the userpass auth method
	EnvVarPasswordFile = "TERRAFORM_VAULT_PASSWORD_FILE"
	// EnvVarGCPAuthJWT to get the signed JWT for the gcp auth method
	EnvVarGCPAuthJWT = "TERRAFORM_VAULT_GCP_AUTH_JWT"
	// EnvVarVaultAuthJWT to login via the Vault jwt engine.
	EnvVarVaultAuthJWT = "TERRAFORM_VAULT_AUTH_JWT"
	// EnvVarAzureAuthJWT to login into Vault's azure auth engine.
	EnvVarAzureAuthJWT = "TERRAFORM_VAULT_AZURE_AUTH_JWT"

	EnvVarGoogleApplicationCreds = "GOOGLE_APPLICATION_CREDENTIALS"

	// EnvVarKrbSPNEGOToken to get the signed JWT for the gcp auth method
	EnvVarKrbSPNEGOToken = "KRB_SPNEGO_TOKEN"
	// EnvVarKRB5Conf path to the krb5.conf file.
	EnvVarKRB5Conf = "KRB5_CONFIG"
	// EnvVarKRBKeytab path the keytab file.
	EnvVarKRBKeytab = "KRB_KEYTAB"

	// EnvVarRadiusUsername for the Radius auth login
	EnvVarRadiusUsername = "RADIUS_USERNAME"
	// EnvVarRadiusPassword for the Radius auth login
	EnvVarRadiusPassword = "RADIUS_PASSWORD"
	// EnvVarTokenFilename for the TokenFile auth login.
	EnvVarTokenFilename = "TERRAFORM_VAULT_TOKEN_FILENAME"

	// EnvVarVaultConfigPath to override where the Vault configuration is in tests.
	// Note: only used in tests. not used by the provider to read the Vault config.
	EnvVarVaultConfigPath = "VAULT_CONFIG_PATH"
	/*
		common mount types
	*/
	MountTypeDatabase     = "database"
	MountTypePKI          = "pki"
	MountTypeAWS          = "aws"
	MountTypeKMIP         = "kmip"
	MountTypeRabbitMQ     = "rabbitmq"
	MountTypeMongoDBAtlas = "mongodbatlas"
	MountTypeNomad        = "nomad"
	MountTypeKubernetes   = "kubernetes"
	MountTypeUserpass     = "userpass"
	MountTypeCert         = "cert"
	MountTypeGCP          = "gcp"
	MountTypeKerberos     = "kerberos"
	MountTypeRadius       = "radius"
	MountTypeOCI          = "oci"
	MountTypeOIDC         = "oidc"
	MountTypeJWT          = "jwt"
	MountTypeAzure        = "azure"
	MountTypeGitHub       = "github"
	MountTypeAD           = "ad"
	MountTypeLDAP         = "ldap"
	MountTypeConsul       = "consul"
	MountTypeTerraform    = "terraform"
	MountTypeNone         = "none"
	MountTypeSAML         = "saml"
	MountTypeOkta         = "okta"

	/*
		Vault version constants
	*/
	VaultVersion190 = "1.9.0"
	VaultVersion110 = "1.10.0"
	VaultVersion111 = "1.11.0"
	VaultVersion112 = "1.12.0"
	VaultVersion113 = "1.13.0"
	VaultVersion114 = "1.14.0"
	VaultVersion115 = "1.15.0"
	VaultVersion116 = "1.16.0"
	VaultVersion117 = "1.17.0"
	VaultVersion118 = "1.18.0"
	VaultVersion119 = "1.19.0"

	/*
		Vault auth methods
	*/
	AuthMethodAWS      = "aws"
	AuthMethodUserpass = "userpass"
	AuthMethodCert     = "cert"
	AuthMethodGCP      = "gcp"
	AuthMethodKerberos = "kerberos"
	AuthMethodRadius   = "radius"
	AuthMethodOCI      = "oci"
	AuthMethodOIDC     = "oidc"
	AuthMethodJWT      = "jwt"
	AuthMethodAzure    = "azure"

	/*
		misc. path related constants
	*/
	PathDelim        = "/"
	VaultAPIV1Root   = "/v1"
	SysNamespaceRoot = "sys/namespaces/"
)
