package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

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
		CreateContext: managedKeysWrite,
		DeleteContext: managedKeysDelete,
		ReadContext:   managedKeysRead,
		UpdateContext: managedKeysWrite,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPKCS: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Configuration block for PKCS Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysPKCSConfigSchema(),
				},
				MaxItems: 1,
			},
			consts.FieldAWS: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Configuration block for AWS Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysAWSConfigSchema(),
				},
				MaxItems: 1,
			},
			consts.FieldAzure: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Configuration block for Azure Managed Keys",
				Elem: &schema.Resource{
					Schema: managedKeysAzureConfigSchema(),
				},
				MaxItems: 1,
			},
		},
	}
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
			Description: " Controls the ability for Vault to replace through " +
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
	}
}

func setCommonManagedKeysSchema(s schemaMap) schemaMap {
	for k, v := range getCommonManagedKeysSchema() {
		s[k] = v
	}
	return s
}

func managedKeysPKCSConfigSchema() schemaMap {
	s := schemaMap{
		consts.FieldName: {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
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
			Description: "The PIN for login",
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
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The PIN for login",
		},
	}

	return setCommonManagedKeysSchema(s)
}

func managedKeysAWSConfigSchema() schemaMap {
	s := schemaMap{
		consts.FieldName: {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
			Description: "A unique lowercase name that serves as " +
				"identifying the key",
		},
		consts.FieldAWSAccessKey: {
			Type:     schema.TypeString,
			Required: true,
			Description: "The AWS access key to use. This can also " +
				"be provided with the 'AWS_ACCESS_KEY_ID' env variable",
		},
		consts.FieldAWSSecretKey: {
			Type:     schema.TypeString,
			Required: true,
			Description: "The AWS secret key to use. This can also " +
				"be provided with the 'AWS_SECRET_ACCESS_KEY' env variable",
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
			ForceNew: true,
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

func getKeyNameFromConfig(d *schema.ResourceData, configType string) string {
	stateKey := fmt.Sprintf("%s.%d.%s", configType, 0, consts.FieldName)

	return d.Get(stateKey).(string)
}

func readManagedKeysConfigBlock(d *schema.ResourceData, keyType string, sm schemaMap) (string, map[string]interface{}) {
	data := map[string]interface{}{}
	var name string

	blockField := keyType
	for blockKey := range sm {
		stateKey := fmt.Sprintf("%s.%d.%s", blockField, 0, blockKey)
		if v, ok := d.GetOk(stateKey); ok {
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

func managedKeysWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if _, ok := d.GetOk(consts.FieldAWS); ok {
		awsKeyName, awsData := readManagedKeysConfigBlock(d, consts.FieldAWS, managedKeysAWSConfigSchema())
		awsKeyPath := getManagedKeysPath(kmsTypeAWS, awsKeyName)

		if _, err := client.Logical().Write(awsKeyPath, awsData); err != nil {
			return diag.Errorf("error writing managed key %q, err=%s", awsKeyPath, err)
		}
	}

	if _, ok := d.GetOk(consts.FieldPKCS); ok {
		pkcsKeyName, pkcsData := readManagedKeysConfigBlock(d, consts.FieldPKCS, managedKeysPKCSConfigSchema())
		pkcsKeyPath := getManagedKeysPath(kmsTypePKCS, pkcsKeyName)

		if _, err := client.Logical().Write(pkcsKeyPath, pkcsData); err != nil {
			return diag.Errorf("error writing managed key %q, err=%s", pkcsKeyPath, err)
		}
	}

	if _, ok := d.GetOk(consts.FieldAzure); ok {
		azureKeyName, azureData := readManagedKeysConfigBlock(d, consts.FieldAzure, managedKeysAzureConfigSchema())
		azureKeyPath := getManagedKeysPath(kmsTypeAzure, azureKeyName)

		if _, err := client.Logical().Write(azureKeyPath, azureData); err != nil {
			return diag.Errorf("error writing managed key %q, err=%s", azureKeyPath, err)
		}
	}

	d.SetId("sys/managed-keys")

	return managedKeysRead(ctx, d, meta)
}

func readAWSManagedKeys(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	awsKeyName := getKeyNameFromConfig(d, consts.FieldAWS)
	awsKeyPath := getManagedKeysPath(kmsTypeAWS, awsKeyName)
	resp, err := client.Logical().Read(awsKeyPath)
	if err != nil {
		return err
	}

	data := map[string]interface{}{}
	for k := range managedKeysAWSConfigSchema() {
		if v, ok := resp.Data[k]; ok {
			data[k] = v
		}

		// set these from TF config since they won't
		// be returned from Vault
		if k == "access_key" || k == "secret_key" {
			stateKey := fmt.Sprintf("%s.%d.%s", consts.FieldAWS, 0, k)
			data[k] = d.Get(stateKey)
		}
	}
	if err := d.Set(consts.FieldAWS, []map[string]interface{}{data}); err != nil {
		return err
	}

	return nil
}

func readAzureManagedKeys(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	azureKeyName := getKeyNameFromConfig(d, consts.FieldAzure)
	azureKeyPath := getManagedKeysPath(kmsTypeAzure, azureKeyName)
	resp, err := client.Logical().Read(azureKeyPath)
	if err != nil {
		return err
	}

	data := map[string]interface{}{}
	for k := range managedKeysAzureConfigSchema() {
		if v, ok := resp.Data[k]; ok {
			data[k] = v
		}
	}
	if err := d.Set(consts.FieldAzure, []map[string]interface{}{data}); err != nil {
		return err
	}

	return nil
}

func readPKCSManagedKeys(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	pkcsKeyName := getKeyNameFromConfig(d, consts.FieldPKCS)
	pkcsKeyPath := getManagedKeysPath(kmsTypePKCS, pkcsKeyName)
	resp, err := client.Logical().Read(pkcsKeyPath)
	if err != nil {
		return err
	}

	data := map[string]interface{}{}
	for k := range managedKeysPKCSConfigSchema() {
		if v, ok := resp.Data[k]; ok {
			data[k] = v
		}

		// set these from TF config since they won't
		// be returned from Vault
		if k == "pin" {
			stateKey := fmt.Sprintf("%s.%d.%s", consts.FieldPKCS, 0, k)
			data[k] = d.Get(stateKey)
		}
	}
	if err := d.Set(consts.FieldPKCS, []map[string]interface{}{data}); err != nil {
		return err
	}

	return nil
}

func managedKeysRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	diags := diag.Diagnostics{}

	if _, ok := d.GetOk(consts.FieldAWS); ok {
		err := readAWSManagedKeys(d, meta)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  fmt.Sprintf("Failed to read AWS Managed Keys, err=%s", err),
			})
		}
	}

	if _, ok := d.GetOk(consts.FieldPKCS); ok {
		err := readPKCSManagedKeys(d, meta)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  fmt.Sprintf("Failed to read PKCS Managed Keys, err=%s", err),
			})
		}
	}

	if _, ok := d.GetOk(consts.FieldAzure); ok {
		err := readAzureManagedKeys(d, meta)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  fmt.Sprintf("Failed to read Azure Managed Keys, err=%s", err),
			})
		}
	}

	return nil
}

func managedKeysDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if _, ok := d.GetOk(consts.FieldAWS); ok {
		awsKeyName := getKeyNameFromConfig(d, consts.FieldAWS)
		path := getManagedKeysPath(kmsTypeAWS, awsKeyName)

		log.Printf("[DEBUG] Deleting managed key %s", path)
		_, err := client.Logical().Delete(path)
		if err != nil {
			return diag.Errorf("error deleting managed key %s", path)
		}
		log.Printf("[DEBUG] Deleted managed key %q", path)
	}

	if _, ok := d.GetOk(consts.FieldAzure); ok {
		azureKeyName := getKeyNameFromConfig(d, consts.FieldAzure)
		path := getManagedKeysPath(kmsTypeAzure, azureKeyName)

		log.Printf("[DEBUG] Deleting managed key %s", path)
		_, err := client.Logical().Delete(path)
		if err != nil {
			return diag.Errorf("error deleting managed key %s", path)
		}
		log.Printf("[DEBUG] Deleted managed key %q", path)
	}

	return nil
}
