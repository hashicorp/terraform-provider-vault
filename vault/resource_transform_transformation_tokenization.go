package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const transformTransformationTokenizationEndpoint = "/transform/transformations/tokenization/{name}"

func transformTransformationTokenizationResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldPath: {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: `The mount path for a back-end, for example, the path given in "$ vault auth enable -path=my-aws aws".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		consts.FieldName: {
			Type:        schema.TypeString,
			Description: "The name of the transformation.",
			ForceNew:    true,
			Required:    true,
		},
		consts.FieldMappingMode: {
			Type: schema.TypeString,
			Description: "Specifies the mapping mode for stored tokenization values. " +
				"default is strongly recommended for highest security. " +
				"exportable allows for all plaintexts to be decoded via the export-decoded endpoint in an emergency.",
			Optional: true,
			Computed: true,
			ForceNew: true,
		},
		consts.FieldConvergent: {
			Type:     schema.TypeBool,
			Optional: true,
			ForceNew: true,
			Description: "Specifies whether to use convergent tokenization, where tokenization of the same plaintext more than once results in the same token. " +
				"Defaults to false as unique tokens are more desirable from a security standpoint if there isn't a use-case need for convergence. " +
				"This property cannot be changed after the transform is created.",
		},
		consts.FieldMaxTTL: {
			Type:        schema.TypeInt,
			Description: "The maximum TTL of a token. If 0 or unspecified, tokens may have no expiration.",
			Optional:    true,
			Computed:    true,
		},
		consts.FieldAllowedRoles: {
			Type: schema.TypeList,
			Description: "Specifies a list of allowed roles that this transformation can be assigned to. " +
				"A role using this transformation must exist in this list in order for encode and decode operations to properly function.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
		},
		consts.FieldStores: {
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description: "The list of tokenization stores to use for tokenization state. " +
				"Vault's internal storage is used by default.",
			Optional: true,
			Computed: true,
			ForceNew: true,
		},
		consts.FieldDeletionAllowed: {
			Type: schema.TypeBool,
			Description: "If true, this transform can be deleted. " + "Otherwise deletion is blocked while this value remains false. " +
				"Note that deleting the transform deletes the underlying key making decoding of tokenized values impossible without restoring from a backup.",
			Optional: true,
		},
	}
	return &schema.Resource{
		CreateContext: createTransformTransformationTokenizationResource,
		ReadContext:   readTransformTransformationTokenizationResource,
		DeleteContext: deleteTransformTransformationTokenizationResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		UpdateContext: updateTransformTransformationTokenizationResource,
		Schema:        fields,
	}
}

func createTransformTransformationTokenizationResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Get(consts.FieldPath).(string)
	vaultPath := util.ParsePath(path, transformTransformationTokenizationEndpoint, d)
	log.Printf("[DEBUG] Creating %q", vaultPath)
	data := map[string]interface{}{}
	for _, v := range []string{consts.FieldMappingMode, consts.FieldMaxTTL, consts.FieldAllowedRoles, consts.FieldStores} {
		if val, ok := d.GetOk(v); ok {
			data[v] = val
		}
	}
	for _, v := range []string{consts.FieldConvergent, consts.FieldDeletionAllowed} {
		if raw, _ := d.GetRawConfigAt(cty.GetAttrPath(v)); !raw.IsNull() {
			data[v] = d.Get(v)
		}
	}
	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return diag.Errorf("error writing %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Wrote %q", vaultPath)

	d.SetId(vaultPath)
	return readTransformTransformationTokenizationResource(ctx, d, meta)
}

func updateTransformTransformationTokenizationResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	vaultPath := d.Id()
	log.Printf("[DEBUG] Updating %q", vaultPath)
	data := map[string]interface{}{}
	for _, v := range []string{consts.FieldMaxTTL, consts.FieldAllowedRoles} {
		if val, ok := d.GetOk(v); ok {
			data[v] = val
		}
	}
	if raw, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldDeletionAllowed)); !raw.IsNull() {
		data[consts.FieldDeletionAllowed] = d.Get(consts.FieldDeletionAllowed)
	}
	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return diag.Errorf("error writing %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Wrote %q", vaultPath)

	d.SetId(vaultPath)
	return readTransformTransformationTokenizationResource(ctx, d, meta)
}

func readTransformTransformationTokenizationResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	vaultPath := d.Id()
	log.Printf("[DEBUG] Reading from %q", vaultPath)
	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return diag.Errorf("error reading %q: %s", vaultPath, err)
	}
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}

	pathParams, err := util.PathParameters(transformTransformationTokenizationEndpoint, vaultPath)
	if err != nil {
		return diag.FromErr(err)
	}
	for paramName, paramVal := range pathParams {
		if err := d.Set(paramName, paramVal); err != nil {
			return diag.Errorf("error setting state %q, %q: %s", paramName, paramVal, err)
		}
	}
	fields := []string{
		consts.FieldMappingMode,
		consts.FieldConvergent,
		consts.FieldMaxTTL,
		consts.FieldAllowedRoles,
		consts.FieldStores,
		consts.FieldDeletionAllowed,
	}
	for _, field := range fields {
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return diag.Errorf("error setting state key %q: %s", field, err)
			}
		}
	}
	return nil
}

func deleteTransformTransformationTokenizationResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	vaultPath := d.Id()
	log.Printf("[DEBUG] Deleting %q", vaultPath)

	if _, err := client.Logical().Delete(vaultPath); err != nil && !util.Is404(err) {
		return diag.Errorf("Error deleting %q: %s", vaultPath, err)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Deleted tokenization transformation at: %q", vaultPath)
	return nil
}
