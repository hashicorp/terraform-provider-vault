package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	keyConfigResource = "/transform/tokenization/keys/{name}/config"
)

func transformKeyConfigResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"path": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: `The mount path for the transform backend, for example the path given in "$ vault secrets enable -path=transform transform".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The name of the transform.",
			ForceNew:    true,
		},
		consts.FieldMinDecryptionVersion: {
			Type:        schema.TypeInt,
			Description: "Minimum key version that vault uses to decode values for the transform",
			Optional:    true,
		},
		consts.FieldAutoRotatePeriod: {
			Type:        schema.TypeInt,
			Description: "Amount of time the key should live before being automatically rotated. A value of 0 disables automatic rotation for the key.",
			Optional:    true,
		},
		consts.FieldMinAvailableVersion: {
			Type:        schema.TypeInt,
			Description: "Minimum key version available for use",
			Computed:    true,
		},
		consts.FieldLatestVersion: {
			Type:        schema.TypeInt,
			Description: "Latest key version available for use",
			Computed:    true,
		},
	}
	return &schema.Resource{
		CreateContext: createTransformKeyConfigResource,
		ReadContext:   provider.ReadContextWrapper(readTransformKeyConfigResource),
		UpdateContext: updateTransformKeyConfigResource,
		DeleteContext: deleteTransformKeyConfigResource,
		Schema:        fields,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func createTransformKeyConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Get("path").(string)
	vaultPath := util.ParsePath(path, keyConfigResource, d)
	log.Printf("[DEBUG] Creating %q", vaultPath)

	data := map[string]interface{}{}
	if version, ok := d.GetOk(consts.FieldMinDecryptionVersion); ok {
		data[consts.FieldMinDecryptionVersion] = version
	}
	if rotatePeriod, ok := d.GetOk(consts.FieldAutoRotatePeriod); ok {
		data[consts.FieldAutoRotatePeriod] = rotatePeriod
	}
	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return diag.Errorf("error writing %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Wrote %q", vaultPath)

	d.SetId(vaultPath)
	return readTransformKeyConfigResource(ctx, d, meta)
}

func readTransformKeyConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	vaultPath := strings.TrimSuffix(d.Id(), "/config")
	endpoint := strings.TrimSuffix(keyConfigResource, "/config")

	log.Printf("[DEBUG] Reading %q", vaultPath)
	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return diag.Errorf("error reading %q: %s", vaultPath, err)
	}
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}

	pathParams, err := util.PathParameters(endpoint, vaultPath)
	if err != nil {
		return diag.FromErr(err)
	}
	for paramName, paramVal := range pathParams {
		if err := d.Set(paramName, paramVal); err != nil {
			return diag.Errorf("error setting state %q, %q: %s", paramName, paramVal, err)
		}
	}

	fields := []string{consts.FieldLatestVersion, consts.FieldMinAvailableVersion, consts.FieldMinDecryptionVersion, consts.FieldAutoRotatePeriod}
	for _, field := range fields {
		if v, ok := resp.Data[field]; ok {
			if err := d.Set(field, v); err != nil {
				return diag.Errorf("error setting state key %q: err=%s", field, err)
			}
		}
	}

	return nil
}

func updateTransformKeyConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	vaultPath := d.Id()
	log.Printf("[DEBUG] Updating %q", vaultPath)

	data := map[string]interface{}{}
	if version, ok := d.GetOk(consts.FieldMinDecryptionVersion); ok {
		data[consts.FieldMinDecryptionVersion] = version
	}
	if rotatePeriod, ok := d.GetOk(consts.FieldAutoRotatePeriod); ok {
		data[consts.FieldAutoRotatePeriod] = rotatePeriod
	}
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return diag.Errorf("error updating %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Updated %q", vaultPath)
	return readTransformKeyConfigResource(ctx, d, meta)
}

func deleteTransformKeyConfigResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}
