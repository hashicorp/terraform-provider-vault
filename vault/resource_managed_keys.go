package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	KMSTypePKCS   = "pkcs11"
	AWSTypePKCS   = "awskms"
	AzureTypePKCS = "azurekeyvault"
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
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "A unique lowercase name that serves as " +
					"identifying the key",
			},

			"type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "The backend type that will be leveraged for the " +
					"managed key. Supported options are 'pkcs11', 'awskms' " +
					"and 'azurekeyvault'",
			},

			"allow_generate_key": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "If no existing key can be found in the referenced " +
					"backend, instructs Vault to generate a key within the backend",
			},

			"allow_store_key": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Controls the ability for Vault to import a key to the " +
					"configured backend, if 'false', those operations will be forbidden",
			},

			"any_mount": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Allow usage from any mount point within the namespace if 'true'",
			},
		},
	}
}

func getManagedKeysPath(keyType, name string) string {
	return fmt.Sprintf("sys/managed-keys/%s/%s", keyType, name)
}

func managedKeysWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get("name").(string)
	keyType := d.Get("type").(string)

	path := getManagedKeysPath(keyType, name)

	data := map[string]interface{}{}
	fields := []string{"allow_generate_key", "allow_store_key", "any_mount"}

	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v.(string)
		}
	}

	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error writing managed key %q, err=%s", path, err)
	}

	d.SetId(path)

	return managedKeysRead(ctx, d, meta)
}

func managedKeysRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.FromErr(err)
	}

	fields := []string{"allow_generate_key", "allow_store_key", "any_mount"}

	for _, k := range fields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}

func managedKeysDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting managed key %s", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting managed key %s", path)
	}
	log.Printf("[DEBUG] Deleted managed key %q", path)

	return nil
}
