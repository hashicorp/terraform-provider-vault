// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	kmsTypePKCS  = "pkcs11"
	kmsTypeAWS   = "awskms"
	kmsTypeAzure = "azurekeyvault"
	kmsTypeGCP   = "gcpckms"
)

type managedKeysConfig struct {
	providerType string
	keyType      string
	schemaFunc   func() schemaMap
}

var (
	managedKeysAWSConfig = &managedKeysConfig{
		providerType: consts.FieldAWS,
		keyType:      kmsTypeAWS,
		schemaFunc:   managedKeysAWSConfigSchema,
	}

	managedKeysAzureConfig = &managedKeysConfig{
		providerType: consts.FieldAzure,
		keyType:      kmsTypeAzure,
		schemaFunc:   managedKeysAzureConfigSchema,
	}

	managedKeysPKCSConfig = &managedKeysConfig{
		providerType: consts.FieldPKCS,
		keyType:      kmsTypePKCS,
		schemaFunc:   managedKeysPKCSConfigSchema,
	}

	managedKeysGCPConfig = &managedKeysConfig{
		providerType: consts.FieldGCP,
		keyType:      kmsTypeGCP,
		schemaFunc:   managedKeysGCPConfigSchema,
	}

	managedKeyProviders = []*managedKeysConfig{
		managedKeysAWSConfig,
		managedKeysAzureConfig,
		managedKeysPKCSConfig,
		managedKeysGCPConfig,
	}
)

func getManagedKeyConfig(providerType string) (*managedKeysConfig, error) {
	for _, config := range managedKeyProviders {
		if config.providerType == providerType {
			return config, nil
		}
	}

	return nil, fmt.Errorf("invalid provider type %s", providerType)
}

func managedKeysResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(createUpdateManagedKeys, provider.VaultVersion110),
		DeleteContext: deleteManagedKeys,
		ReadContext:   readManagedKeys,
		UpdateContext: createUpdateManagedKeys,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			managedKeysPKCSConfig.providerType: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Configuration block for PKCS Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysPKCSConfig.schemaFunc(),
				},
				Set: hashManagedKeys,
			},
			managedKeysAWSConfig.providerType: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Configuration block for AWS Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysAWSConfig.schemaFunc(),
				},
				Set: hashManagedKeys,
			},
			managedKeysAzureConfig.providerType: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Configuration block for Azure Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysAzureConfig.schemaFunc(),
				},
				Set: hashManagedKeys,
			},
			managedKeysGCPConfig.providerType: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Configuration block for GCP Cloud KMS Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysGCPConfig.schemaFunc(),
				},
				Set: hashManagedKeys,
			},
		},
	}
}

func hashManagedKeys(v interface{}) int {
	var result int
	if m, ok := v.(map[string]interface{}); ok {
		if v, ok := m[consts.FieldName]; ok {
			result = getHashFromName(v.(string))
		}
	}

	return result
}

var getHashFromName = helper.HashCodeString

func getCommonManagedKeysSchema() schemaMap {
	return schemaMap{
		consts.FieldAllowGenerateKey: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
			Description: "If no existing key can be found in the referenced " +
				"backend, instructs Vault to generate a key within the backend",
		},

		consts.FieldAllowReplaceKey: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
			Description: "Controls the ability for Vault to replace through " +
				"generation or importing a key into the configured backend even " +
				"if a key is present, if set to false those operations are forbidden " +
				"if a key exists.",
		},

		consts.FieldAllowStoreKey: {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
			Description: "Controls the ability for Vault to import a key to the " +
				"configured backend, if 'false', those operations will be forbidden",
		},

		consts.FieldAnyMount: {
			Type:        schema.TypeBool,
			Optional:    true,
			Computed:    true,
			Description: "Allow usage from any mount point within the namespace if 'true'",
		},

		consts.FieldUsages: {
			Type:        schema.TypeList,
			Optional:    true,
			Computed:    true,
			Description: "A comma-delimited list of allowed uses for this key. Valid values: encrypt, decrypt, sign, verify, wrap, unwrap, mac, random",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},

		consts.FieldUUID: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the managed key read from Vault",
		},
	}
}

func setCommonManagedKeysSchema(s schemaMap) schemaMap {
	for k, v := range getCommonManagedKeysSchema() {
		if _, ok := s[k]; ok {
			panic(fmt.Sprintf("cannot add schema field %q, already exists in the Schema map", k))
		}

		s[k] = v
	}
	return s
}

func managedKeysPKCSConfigSchema() schemaMap {
	s := schemaMap{
		consts.FieldName: {
			Type:     schema.TypeString,
			Required: true,
			Description: "A unique lowercase name that serves as " +
				"identifying the key",
		},
		consts.FieldLibrary: {
			Type:     schema.TypeString,
			Required: true,
			Description: "The name of the kms_library stanza to use from Vault's config " +
				"to lookup the local library path",
		},
		consts.FieldKeyLabel: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The label of the key to use",
		},
		consts.FieldKeyID: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The id of a PKCS#11 key to use",
		},
		consts.FieldMechanism: {
			Type:     schema.TypeString,
			Required: true,
			Description: "The encryption/decryption mechanism to use, specified as a " +
				"hexadecimal (prefixed by 0x) string.",
		},
		consts.FieldPin: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The PIN for login",
		},
		consts.FieldSlot: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "The slot number to use, specified as a string in a " +
				"decimal format (e.g. '2305843009213693953')",
		},
		consts.FieldTokenLabel: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The slot token label to use",
		},
		consts.FieldCurve: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Supplies the curve value when using " +
				"the 'CKM_ECDSA' mechanism. Required if " +
				"'allow_generate_key' is true",
		},
		consts.FieldKeyBits: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Supplies the size in bits of the key when using " +
				"'CKM_RSA_PKCS_PSS', 'CKM_RSA_PKCS_OAEP' or 'CKM_RSA_PKCS' " +
				"as a value for 'mechanism'. Required if " +
				"'allow_generate_key' is true",
		},
		consts.FieldForceRWSession: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Force all operations to open up a read-write session " +
				"to the HSM",
		},
		consts.FieldMaxParallel: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "The number of concurrent requests that may be in flight to the HSM at any given time",
		},
	}

	return setCommonManagedKeysSchema(s)
}

func managedKeysAWSConfigSchema() schemaMap {
	s := schemaMap{
		consts.FieldName: {
			Type:     schema.TypeString,
			Required: true,
			Description: "A unique lowercase name that serves as " +
				"identifying the key",
		},
		consts.FieldAccessKey: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The AWS access key to use",
		},
		consts.FieldSecretKey: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The AWS secret key to use",
		},
		consts.FieldCurve: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "The curve to use for an ECDSA key. Used " +
				"when key_type is 'ECDSA'. Required if " +
				"'allow_generate_key' is true",
		},
		consts.FieldEndpoint: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Used to specify a custom AWS endpoint",
		},
		consts.FieldKeyBits: {
			Type:     schema.TypeString,
			Required: true,
			Description: "The size in bits for an RSA key. This " +
				"field is required when 'key_type' is 'RSA'",
		},
		consts.FieldKeyType: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The type of key to use",
		},
		consts.FieldKMSKey: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "An identifier for the key",
		},
		consts.FieldRegion: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The AWS region where the keys are stored (or will be stored)",
		},
	}

	return setCommonManagedKeysSchema(s)
}

func managedKeysAzureConfigSchema() schemaMap {
	s := schemaMap{
		consts.FieldName: {
			Type:     schema.TypeString,
			Required: true,
			Description: "A unique lowercase name that serves as " +
				"identifying the key",
		},
		consts.FieldTenantID: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The tenant id for the Azure Active Directory organization",
		},
		consts.FieldClientID: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The client id for credentials to query the Azure APIs",
		},
		consts.FieldClientSecret: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The client secret for credentials to query the Azure APIs",
		},
		consts.FieldEnvironment: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The Azure Cloud environment API endpoints to use",
		},
		consts.FieldVaultName: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The Key Vault vault to use the encryption keys for encryption and decryption",
		},
		consts.FieldKeyName: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The Key Vault key to use for encryption and decryption",
		},
		consts.FieldResource: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The Azure Key Vault resource's DNS Suffix to connect to",
		},
		consts.FieldKeyBits: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "The size in bits for an RSA key. This field is required " +
				"when 'key_type' is 'RSA' or when 'allow_generate_key' is true",
		},
		consts.FieldKeyType: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The type of key to use",
		},
	}

	return setCommonManagedKeysSchema(s)
}

func managedKeysGCPConfigSchema() schemaMap {
	s := schemaMap{
		consts.FieldName: {
			Type:     schema.TypeString,
			Required: true,
			Description: "A unique lowercase name that serves as " +
				"identifying the key",
		},
		consts.FieldCredentials: {
			Type:     schema.TypeString,
			Required: true,
			Description: "The path to the credentials JSON file to use for " +
				"authenticating to GCP. Alternatively set via the GOOGLE_CREDENTIALS " +
				"or GOOGLE_APPLICATION_CREDENTIALS environment variables",
		},
		consts.FieldProject: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The GCP project ID. Can also be provided via the GOOGLE_PROJECT environment variable",
		},
		consts.FieldKeyRing: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The name of the key ring in GCP Cloud KMS. This needs to be created prior to key creation",
		},
		consts.FieldCryptoKey: {
			Type:     schema.TypeString,
			Required: true,
			Description: "The name of the GCP Cloud KMS key. If no existing key " +
				"exists and allow_generate_key is true, Vault will generate a key with this name",
		},
		consts.FieldCryptoKeyVersion: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The version of the key to use. Default: 1",
		},
		consts.FieldRegion: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The GCP region where the key ring was created. Can also be provided via the GOOGLE_REGION environment variable",
		},
		consts.FieldAlgorithm: {
			Type:     schema.TypeString,
			Required: true,
			Description: "The signature algorithm to be used with the key. " +
				"Supported values: ec_sign_p256_sha256, ec_sign_p384_sha384, " +
				"rsa_sign_pss_2048_sha256, rsa_sign_pss_3072_sha256, rsa_sign_pss_4096_sha256, " +
				"rsa_sign_pss_4096_sha512, rsa_sign_pkcs1_2048_sha256, rsa_sign_pkcs1_3072_sha256, " +
				"rsa_sign_pkcs1_4096_sha256, rsa_sign_pkcs1_4096_sha512",
		},
		consts.FieldMaxParallel: {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "The number of concurrent requests that may be in flight to GCP Cloud KMS at any given time",
		},
	}

	return setCommonManagedKeysSchema(s)
}

func getManagedKeysConfigData(config map[string]interface{}, sm schemaMap) (string, map[string]interface{}) {
	data := map[string]interface{}{}
	var name string

	for blockKey := range sm {
		if v, ok := config[blockKey]; ok {
			// ensure empty strings are not written
			// to vault as part of the data
			if s, ok := v.(string); ok && s == "" {
				continue
			}

			// Convert usages list to comma-delimited string for Vault API
			if blockKey == consts.FieldUsages {
				if usagesList, ok := v.([]interface{}); ok && len(usagesList) > 0 {
					usages := make([]string, len(usagesList))
					for i, usage := range usagesList {
						usages[i] = usage.(string)
					}
					data[blockKey] = strings.Join(usages, ",")
				}
				continue
			}

			data[blockKey] = v

			if blockKey == consts.FieldName {
				name = v.(string)
			}
		}
	}

	return name, data
}

func getManagedKeysPathPrefix(keyType string) string {
	return fmt.Sprintf("sys/managed-keys/%s", keyType)
}

func getManagedKeysPath(keyType, name string) string {
	return fmt.Sprintf("%s/%s", getManagedKeysPathPrefix(keyType), name)
}

func isUnsupportedKeyTypeError(err error) bool {
	return strings.Contains(err.Error(), "unsupported managed key type")
}

func isProviderSupportRequired(d *schema.ResourceData, providerType string) bool {
	// is provider required
	_, ok := d.GetOk(providerType)
	return ok
}

func handleKeyProviderRequired(d *schema.ResourceData, providerType string, err error) error {
	isUnsupported := isUnsupportedKeyTypeError(err)
	if isUnsupported && isProviderSupportRequired(d, providerType) {
		return fmt.Errorf("managed key type %s is not supported by this version of Vault, err=%s",
			providerType, err)
	}

	if !isUnsupported {
		return err
	}

	return nil
}

func writeManagedKeysData(d *schema.ResourceData, client *api.Client, providerType string) diag.Diagnostics {
	config, err := getManagedKeyConfig(providerType)
	if err != nil {
		return diag.FromErr(err)
	}

	// confirm that managed keys are not already configured
	if d.IsNewResource() {
		for _, c := range managedKeyProviders {
			p := getManagedKeysPathPrefix(c.keyType)
			resp, err := client.Logical().List(p)
			if err != nil {
				if err := handleKeyProviderRequired(d, c.providerType, err); err != nil {
					return diag.FromErr(err)
				}
			}

			if resp == nil {
				continue
			}

			if v, ok := resp.Data["keys"]; ok {
				if len(v.([]interface{})) > 0 {
					return diag.FromErr(fmt.Errorf("managed keys already exist in Vault; use 'terraform import' instead"))
				}
			}
		}
	}

	oldKeySet := map[string]bool{}
	oldBlocks, newBlocks := d.GetChange(providerType)

	// populate the set of old keys
	for _, block := range oldBlocks.(*schema.Set).List() {
		m := block.(map[string]interface{})
		name := m[consts.FieldName].(string)
		oldKeySet[name] = true
	}

	newKeySet := map[string]bool{}
	for _, block := range newBlocks.(*schema.Set).List() {
		keyName, data := getManagedKeysConfigData(block.(map[string]interface{}), config.schemaFunc())

		if err := validateConfigData(providerType, data); err != nil {
			return diag.Errorf("bad configuration for %s: %v", keyName, err)
		}
		path := getManagedKeysPath(config.keyType, keyName)

		log.Printf("[DEBUG] Writing data to Vault at %s", path)
		if _, err := client.Logical().Write(path, data); err != nil {
			return diag.Errorf("error writing managed key %q, err=%s", path, err)
		}

		// populate the set of new keys
		newKeySet[keyName] = true
	}

	// Flush out all unused keys
	// This also handles the case of an update on 'name'
	for k := range oldKeySet {
		if !newKeySet[k] {
			// Delete single key type
			if diags := deleteSingleManagedKey(client, config.keyType, k); diags != nil {
				return diags
			}
		}
	}

	return nil
}

// atLeastOne doesn't work in SDKv2 if the fields in question are in a nested block
func validateConfigData(name string, data map[string]interface{}) error {
	if name != consts.FieldPKCS {
		return nil
	}
	_, okID := data[consts.FieldKeyID]
	_, okLabel := data[consts.FieldKeyLabel]
	if !okID && !okLabel {
		return fmt.Errorf("at least one of %s or %s must be provided", consts.FieldKeyID, consts.FieldKeyLabel)
	}

	return nil
}

func createUpdateManagedKeys(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if _, ok := d.GetOk(consts.FieldAWS); ok {
		if diags := writeManagedKeysData(d, client, consts.FieldAWS); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldPKCS); ok {
		if diags := writeManagedKeysData(d, client, consts.FieldPKCS); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldAzure); ok {
		if diags := writeManagedKeysData(d, client, consts.FieldAzure); diags != nil {
			return diags
		}
	}

	// set ID to 'default'
	d.SetId("default")

	return readManagedKeys(ctx, d, meta)
}

func updateRedactedFields(d *schema.ResourceData, providerType, name string,
	fields []string, m map[string]interface{},
) {
	prefix := fmt.Sprintf("%s.%d.", providerType, getHashFromName(name))
	for _, field := range fields {
		k := prefix + field
		if v, ok := d.GetOk(k); ok {
			m[field] = v
		}
	}
}

func readAndSetManagedKeys(d *schema.ResourceData, client *api.Client, providerType string,
	sm map[string]string, redactedFields []string,
) error {
	config, err := getManagedKeyConfig(providerType)
	if err != nil {
		return err
	}

	p := getManagedKeysPathPrefix(config.keyType)
	log.Printf("[DEBUG] Listing data from Vault at %s", p)
	resp, err := client.Logical().List(p)
	if err != nil {
		if err := handleKeyProviderRequired(d, providerType, err); err != nil {
			return err
		}
	}

	if resp == nil {
		return nil
	}

	var data []interface{}
	if v, ok := resp.Data["keys"]; ok {
		for _, name := range v.([]interface{}) {
			m := make(map[string]interface{})
			// set fields from TF config
			// these values are returned as "redacted" from Vault
			updateRedactedFields(d, providerType, name.(string), redactedFields, m)

			path := getManagedKeysPath(config.keyType, name.(string))
			log.Printf("[DEBUG] Reading from Vault at %s", path)
			resp, err := client.Logical().Read(path)
			if err != nil {
				return err
			}

			if resp == nil {
				continue
			}

			for k := range config.schemaFunc() {
				// Skip reading usages field as Vault returns it in an incompatible numeric format
				// We'll keep using the value from Terraform config
				if k == consts.FieldUsages {
					continue
				}

				// Map TF schema fields to Vault API
				vaultKey := k
				if v, ok := sm[k]; ok {
					vaultKey = v
				}

				if v, ok := resp.Data[vaultKey]; ok {
					// log an out-of-band change on UUID
					if vaultKey == "UUID" {
						stateKey := fmt.Sprintf("%s.%d.%s", providerType, getHashFromName(name.(string)), k)

						if id, ok := d.GetOk(stateKey); ok && id.(string) != "" {
							// check if UUID in TF state is different
							if id.(string) != v.(string) {
								log.Printf("[DEBUG] Out-of-band change detected for %q,  vault has %s, was %s for path=%q", stateKey, v, id, path)
							}
						}
					}

					if _, ok := m[k]; ok {
						continue
					}

					m[k] = v
				}
			}

			data = append(data, m)
		}
	}

	s := schema.NewSet(hashManagedKeys, data)

	if err := d.Set(providerType, s); err != nil {
		return err
	}

	return nil
}

func readAWSManagedKeys(d *schema.ResourceData, client *api.Client) error {
	redacted := []string{consts.FieldAccessKey, consts.FieldSecretKey}
	// usages is also preserved from config since Vault returns it in an incompatible numeric format
	preservedFields := append(redacted, consts.FieldUsages)
	if err := readAndSetManagedKeys(d, client, consts.FieldAWS,
		map[string]string{consts.FieldUUID: "UUID"}, preservedFields); err != nil {
		return err
	}

	return nil
}

func readAzureManagedKeys(d *schema.ResourceData, client *api.Client) error {
	// usages is preserved from config since Vault returns it in an incompatible numeric format
	preservedFields := []string{consts.FieldUsages}
	if err := readAndSetManagedKeys(d, client, consts.FieldAzure,
		map[string]string{consts.FieldUUID: "UUID"}, preservedFields); err != nil {
		return err
	}

	return nil
}

func readPKCSManagedKeys(d *schema.ResourceData, client *api.Client) error {
	redacted := []string{consts.FieldPin, consts.FieldKeyID}
	// usages is also preserved from config since Vault returns it in an incompatible numeric format
	preservedFields := append(redacted, consts.FieldUsages)
	if err := readAndSetManagedKeys(d, client, consts.FieldPKCS,
		map[string]string{consts.FieldUUID: "UUID"}, preservedFields); err != nil {
		return err
	}

	return nil
}

func readGCPManagedKeys(d *schema.ResourceData, client *api.Client) error {
	// credentials and usages are preserved from config
	preservedFields := []string{consts.FieldCredentials, consts.FieldUsages}
	if err := readAndSetManagedKeys(d, client, consts.FieldGCP,
		map[string]string{consts.FieldUUID: "UUID"}, preservedFields); err != nil {
		return err
	}

	return nil
}

func readManagedKeys(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	diags := diag.Diagnostics{}

	if err := readAWSManagedKeys(d, client); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to read AWS Managed Keys, err=%s", err),
		})
	}

	if err := readPKCSManagedKeys(d, client); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to read PKCS Managed Keys, err=%s", err),
		})
	}

	if err := readAzureManagedKeys(d, client); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to read Azure Managed Keys, err=%s", err),
		})
	}

	if err := readGCPManagedKeys(d, client); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to read GCP Cloud KMS Managed Keys, err=%s", err),
		})
	}

	return diags
}

func deleteSingleManagedKey(client *api.Client, keyType, name string) diag.Diagnostics {
	path := getManagedKeysPath(keyType, name)
	log.Printf("[DEBUG] Deleting managed key %s", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting managed key %s", path)
	}
	log.Printf("[DEBUG] Deleted managed key %q", path)

	return nil
}

func deleteManagedKeyType(client *api.Client, keyType string) diag.Diagnostics {
	p := fmt.Sprintf("%s/%s", "sys/managed-keys", keyType)
	resp, err := client.Logical().List(p)
	if err != nil {
		return diag.FromErr(err)
	}

	if resp == nil {
		return nil
	}

	if v, ok := resp.Data["keys"]; ok {
		for _, name := range v.([]interface{}) {
			if diags := deleteSingleManagedKey(client, keyType, name.(string)); diags != nil {
				return diags
			}
		}
	}

	return nil
}

func deleteManagedKeys(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if _, ok := d.GetOk(consts.FieldAWS); ok {
		if diags := deleteManagedKeyType(client, kmsTypeAWS); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldPKCS); ok {
		if diags := deleteManagedKeyType(client, kmsTypePKCS); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldAzure); ok {
		if diags := deleteManagedKeyType(client, kmsTypeAzure); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldGCP); ok {
		if diags := deleteManagedKeyType(client, kmsTypeGCP); diags != nil {
			return diags
		}
	}

	return nil
}
