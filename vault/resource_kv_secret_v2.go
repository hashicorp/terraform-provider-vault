package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretV2Resource(name string) *schema.Resource {
	return &schema.Resource{
		CreateContext: kvSecretV2Write,
		UpdateContext: kvSecretV2Write,
		DeleteContext: kvSecretV2Delete,
		ReadContext:   kvSecretV2Read,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path where KV-V2 engine is mounted.",
			},
			consts.FieldName: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "Full name of the secret. For a nested secret, " +
					"the name is the nested path excluding the mount and data " +
					"prefix. For example, for a secret at 'kvv2/data/foo/bar/baz', " +
					"the name is 'foo/bar/baz'",
			},
			consts.FieldPath: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path where the KV-V2 secret will be written.",
			},
			"cas": {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "This flag is required if cas_required is set to true " +
					"on either the secret or the engine's config. In order for a " +
					"write to be successful, cas must be set to the current version " +
					"of the secret.",
			},
			"options": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "An object that holds option settings.",
			},

			"disable_read": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				Description: "If set to true, disables reading secret from Vault; " +
					"note: drift won't be detected.",
			},

			// Data is passed as JSON so that an arbitrary structure is
			// possible, rather than forcing e.g. all values to be strings.
			"data_json": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "JSON-encoded secret data to write.",
				// We rebuild the attached JSON string to a simple single-line
				// string. These make Terraform not want to change when an extra
				// space is included in the JSON string. It is also necessary
				// when disable_read is false for comparing values.
				StateFunc:    NormalizeDataJSONFunc(name),
				ValidateFunc: ValidateDataJSONFunc(name),
				Sensitive:    true,
			},

			consts.FieldData: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},

			"metadata": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Metadata associated with this secret read from Vault.",
			},

			"delete_all_versions": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set to true, permanently deletes all versions for the specified key.",
			},
		},
	}
}

func getKVV2Path(mount, name, prefix string) string {
	return fmt.Sprintf("%s/%s/%s", mount, prefix, name)
}

func kvSecretV2Write(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.ProviderMeta).GetClient()
	mount := d.Get("mount").(string)
	name := d.Get("name").(string)

	path := getKVV2Path(mount, name, "data")

	var secretData map[string]interface{}
	err := json.Unmarshal([]byte(d.Get("data_json").(string)), &secretData)
	if err != nil {
		return diag.Errorf("data_json %#v syntax error: %s", d.Get("data_json"), err)
	}

	data := map[string]interface{}{
		"data": secretData,
	}

	kvFields := []string{"cas", "options"}
	for _, k := range kvFields {
		data[k] = d.Get(k)
	}

	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error writing secret data to %s, err=%s", path, err)
	}

	d.SetId(path)

	return kvSecretV2Read(ctx, d, meta)
}

func kvSecretV2Read(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	shouldRead := !d.Get("disable_read").(bool)

	path := d.Id()

	if err := d.Set("path", path); err != nil {
		return diag.FromErr(err)
	}

	if shouldRead {
		client := meta.(*provider.ProviderMeta).GetClient()

		log.Printf("[DEBUG] Reading %s from Vault", path)
		secret, err := client.Logical().Read(path)
		if err != nil {
			return diag.Errorf("error reading from Vault: %s", err)
		}
		if secret == nil {
			log.Printf("[WARN] secret (%s) not found, removing from state", path)
			d.SetId("")
			return nil
		}

		log.Printf("[DEBUG] secret: %#v", secret)

		data := secret.Data["data"]

		if err := d.Set("data", serializeDataMapToString(data.(map[string]interface{}))); err != nil {
			return diag.FromErr(err)
		}

		if v, ok := secret.Data["metadata"]; ok {
			if err := d.Set("metadata", serializeDataMapToString(v.(map[string]interface{}))); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}

func kvSecretV2Delete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.ProviderMeta).GetClient()

	mount := d.Get("mount").(string)
	name := d.Get("name").(string)

	base := "data"
	deleteAllVersions := d.Get("delete_all_versions").(bool)
	if deleteAllVersions {
		base = "metadata"
	}

	path := getKVV2Path(mount, name, base)

	log.Printf("[DEBUG] Deleting vault_kv_secret_v2 from %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}
