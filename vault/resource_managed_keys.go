package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	kmsTypePKCS  = "pkcs11"
	kmsTypeAWS   = "awskms"
	kmsTypeAzure = "azurekeyvault"
)

func managedKeysResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: createUpdateManagedKeys,
		DeleteContext: deleteManagedKeys,
		ReadContext:   readManagedKeys,
		UpdateContext: createUpdateManagedKeys,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPKCS: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Configuration block for PKCS Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysPKCSConfigSchema(),
				},
				Set: hashManagedKeys,
			},
			consts.FieldAWS: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Configuration block for AWS Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysAWSConfigSchema(),
				},
				Set: hashManagedKeys,
			},
			consts.FieldAzure: {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Configuration block for Azure Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysAzureConfigSchema(),
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

func getHashFromName(name string) int {
	return helper.HashCodeString(name)
}

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
			Required:    true,
			Description: "The label of the key to use",
		},
		consts.FieldKeyID: {
			Type:        schema.TypeString,
			Required:    true,
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
		consts.FieldAWSAccessKey: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The AWS access key to use",
		},
		consts.FieldAWSSecretKey: {
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
			Default:     "us-east-1",
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
			Default:     "AZUREPUBLICCLOUD",
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
			Default:     "vault.azure.net",
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

func getManagedKeysConfigData(config map[string]interface{}, sm schemaMap) (string, map[string]interface{}) {
	data := map[string]interface{}{}
	var name string

	for blockKey := range sm {
		if v, ok := config[blockKey]; ok {
			data[blockKey] = v

			if blockKey == consts.FieldName {
				name = v.(string)
			}
		}
	}

	return name, data
}

func getManagedKeysPath(keyType, name string) string {
	return fmt.Sprintf("sys/managed-keys/%s/%s", keyType, name)
}

func writeManagedKeysData(d *schema.ResourceData, meta interface{}, providerType string) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	var keyType string
	handlers := map[string]func() schemaMap{
		kmsTypeAWS:   managedKeysAWSConfigSchema,
		kmsTypePKCS:  managedKeysPKCSConfigSchema,
		kmsTypeAzure: managedKeysAzureConfigSchema,
	}

	switch providerType {
	case consts.FieldAWS:
		keyType = kmsTypeAWS

	case consts.FieldPKCS:
		keyType = kmsTypePKCS

	case consts.FieldAzure:
		keyType = kmsTypeAzure

	default:
		return diag.Errorf("received unexpected provider type %s", providerType)
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
		keyName, data := getManagedKeysConfigData(block.(map[string]interface{}), handlers[keyType]())
		path := getManagedKeysPath(keyType, keyName)

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
			if diags := deleteSingleManagedKey(d, meta, keyType, k); diags != nil {
				return diags
			}
		}
	}

	return nil
}

func createUpdateManagedKeys(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if _, ok := d.GetOk(consts.FieldAWS); ok {
		if diags := writeManagedKeysData(d, meta, consts.FieldAWS); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldPKCS); ok {
		if diags := writeManagedKeysData(d, meta, consts.FieldPKCS); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldAzure); ok {
		if diags := writeManagedKeysData(d, meta, consts.FieldAzure); diags != nil {
			return diags
		}
	}

	// set ID to 'default'
	d.SetId("default")

	return readManagedKeys(ctx, d, meta)
}

func getRedactedFields(d *schema.ResourceData, providerType, name string,
	fields []string, m map[string]interface{},
) map[string]interface{} {
	prefix := fmt.Sprintf("%s.%d.", providerType, getHashFromName(name))
	for _, field := range fields {
		k := prefix + field
		if v, ok := d.GetOk(k); ok {
			m[field] = v
		}
	}

	return m
}

func readAndSetManagedKeys(d *schema.ResourceData, meta interface{},
	providerType string, sm map[string]string, redactedFields []string) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	var keyType string
	switch providerType {
	case consts.FieldAWS:
		keyType = kmsTypeAWS

	case consts.FieldPKCS:
		keyType = kmsTypePKCS

	case consts.FieldAzure:
		keyType = kmsTypeAzure

	default:
		return fmt.Errorf("received unexpected provider type %s", providerType)
	}

	p := fmt.Sprintf("%s/%s", "sys/managed-keys", keyType)
	log.Printf("[DEBUG] Listing data from Vault at %s", p)
	resp, err := client.Logical().List(p)
	if err != nil {
		return err
	}

	if resp == nil {
		return nil
	}

	handlers := map[string]func() schemaMap{
		kmsTypeAWS:   managedKeysAWSConfigSchema,
		kmsTypePKCS:  managedKeysPKCSConfigSchema,
		kmsTypeAzure: managedKeysAzureConfigSchema,
	}

	var data []interface{}
	if v, ok := resp.Data["keys"]; ok {
		for _, name := range v.([]interface{}) {
			m := make(map[string]interface{})
			path := getManagedKeysPath(keyType, name.(string))
			log.Printf("[DEBUG] Reading from Vault at %s", path)
			resp, err := client.Logical().Read(path)
			if err != nil {
				return err
			}

			if resp == nil {
				continue
			}

			for k := range handlers[keyType]() {
				// Map TF schema fields to Vault API
				vaultKey := k
				if v, ok := sm[k]; ok {
					vaultKey = v
				}

				if v, ok := resp.Data[vaultKey]; ok {
					m[k] = v
				}
			}

			// get these from TF config since they are
			// returned as "redacted" from Vault
			m = getRedactedFields(d, providerType, name.(string), redactedFields, m)

			data = append(data, m)
		}
	}

	s := schema.NewSet(hashManagedKeys, data)

	if err := d.Set(providerType, s); err != nil {
		return err
	}

	return nil
}

func readAWSManagedKeys(d *schema.ResourceData, meta interface{}) error {
	redacted := []string{"access_key", "secret_key"}
	sm := map[string]string{
		consts.FieldUUID: "UUID",
	}
	if err := readAndSetManagedKeys(d, meta, consts.FieldAWS, sm, redacted); err != nil {
		return err
	}

	return nil
}

func readAzureManagedKeys(d *schema.ResourceData, meta interface{}) error {
	var redacted []string
	sm := map[string]string{
		consts.FieldUUID: "UUID",
	}
	if err := readAndSetManagedKeys(d, meta, consts.FieldAzure, sm, redacted); err != nil {
		return err
	}

	return nil
}

func readPKCSManagedKeys(d *schema.ResourceData, meta interface{}) error {
	redacted := []string{"pin"}
	sm := map[string]string{
		consts.FieldUUID: "UUID",
	}
	if err := readAndSetManagedKeys(d, meta, consts.FieldPKCS, sm, redacted); err != nil {
		return err
	}

	return nil
}

func readManagedKeys(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	diags := diag.Diagnostics{}

	err := readAWSManagedKeys(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to read AWS Managed Keys, err=%s", err),
		})
	}

	err = readPKCSManagedKeys(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to read PKCS Managed Keys, err=%s", err),
		})
	}

	err = readAzureManagedKeys(d, meta)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to read Azure Managed Keys, err=%s", err),
		})
	}

	return diags
}

func deleteSingleManagedKey(d *schema.ResourceData, meta interface{}, keyType, name string) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := getManagedKeysPath(keyType, name)
	log.Printf("[DEBUG] Deleting managed key %s", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting managed key %s", path)
	}
	log.Printf("[DEBUG] Deleted managed key %q", path)

	return nil
}

func deleteManagedKeyType(d *schema.ResourceData, meta interface{}, keyType string) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

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
			if diags := deleteSingleManagedKey(d, meta, keyType, name.(string)); diags != nil {
				return diags
			}
		}
	}

	return nil
}

func deleteManagedKeys(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if _, ok := d.GetOk(consts.FieldAWS); ok {
		if diags := deleteManagedKeyType(d, meta, kmsTypeAWS); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldPKCS); ok {
		if diags := deleteManagedKeyType(d, meta, kmsTypePKCS); diags != nil {
			return diags
		}
	}

	if _, ok := d.GetOk(consts.FieldAzure); ok {
		if diags := deleteManagedKeyType(d, meta, kmsTypeAzure); diags != nil {
			return diags
		}
	}

	return nil
}
