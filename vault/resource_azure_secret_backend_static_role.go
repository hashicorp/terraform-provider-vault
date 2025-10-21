// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	azureStaticRolesAffix = "static-roles"
)

var azureStaticRolesRegex = regexp.MustCompile("^(.+)/static-roles/(.+)$")

func azureSecretBackendStaticRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldBackend: {
			Type:         schema.TypeString,
			Default:      consts.MountTypeAzure,
			Optional:     true,
			Description:  "The path where the Azure secrets backend is mounted.",
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		consts.FieldRole: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role to create",
			ForceNew:    true,
		},
		consts.FieldApplicationObjectID: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Application object ID for an existing service principal that is managed by the static role.",
		},
		consts.FieldTTL: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Timespan of 1 year (`8760h`) or more during which the role credentials are valid.",
		},
		consts.FieldMetadata: {
			Type:        schema.TypeMap,
			Description: "A map of string key/value pairs that will be stored as metadata on the secret.",
			Optional:    true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		consts.FieldSecretID: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The secret ID of the Azure password credential you want to import.",
		},
		consts.FieldClientSecret: {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: "The plaintext secret value of the credential you want to import.",
		},
		consts.FieldExpiration: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "A future expiration time for the imported credential, in RFC3339 format.",
		},
		consts.FieldSkipImportRotation: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Skip rotation of the client secret on import.",
		},
	}
	return &schema.Resource{
		CreateContext: createUpdateAzureStaticRoleResource,
		UpdateContext: createUpdateAzureStaticRoleResource,
		ReadContext:   provider.ReadContextWrapper(readAzureStaticRoleResource),
		DeleteContext: deleteAzureStaticRoleResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

var azureSecretBackendStaticRoleFields = []string{
	consts.FieldApplicationObjectID,
	consts.FieldTTL,
	consts.FieldSecretID,
	consts.FieldClientSecret,
	consts.FieldExpiration,
	consts.FieldSkipImportRotation,
}

func createUpdateAzureStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	role := d.Get(consts.FieldRole).(string)
	rolePath := fmt.Sprintf("%s/%s/%s", backend, azureStaticRolesAffix, role)

	data := map[string]interface{}{}
	useAPIVer121Ent := provider.IsAPISupported(meta, provider.VaultVersion121) && provider.IsEnterpriseSupported(meta)
	if useAPIVer121Ent {
		for _, field := range azureSecretBackendStaticRoleFields {
			if v, ok := d.GetOk(field); ok {
				data[field] = v
			}
		}
		if v, ok := d.GetOk(consts.FieldMetadata); ok {
			m, err := json.Marshal(v.(map[string]interface{}))
			if err != nil {
				return diag.FromErr(fmt.Errorf("encode metadata: %w", err))
			}
			data[consts.FieldMetadata] = string(m)
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, rolePath, data); err != nil {
		return diag.FromErr(fmt.Errorf("error writing %q: %s", rolePath, err))
	}

	d.SetId(rolePath)
	log.Printf("[DEBUG] Wrote %q", rolePath)
	return readAzureStaticRoleResource(ctx, d, meta)
}

func readAzureStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	log.Printf("[DEBUG] Reading %q", path)

	backend, role, err := parseAzureStaticRolePath(path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("invalid id %q; %w", path, err))
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldRole, role); err != nil {
		return diag.FromErr(err)
	}

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	useAPIVer121Ent := provider.IsAPISupported(meta, provider.VaultVersion121) && provider.IsEnterpriseSupported(meta)
	if useAPIVer121Ent {
		for _, field := range azureSecretBackendStaticRoleFields {
			if v, ok := resp.Data[field]; ok {
				if err := d.Set(field, v); err != nil {
					return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", field, err))
				}
			}
		}
		if v, ok := resp.Data[consts.FieldMetadata]; ok {
			if err := NormalizeMap(d, consts.FieldMetadata, v); err != nil {
				return diag.FromErr(fmt.Errorf("error setting metadata: %w", err))
			}
		} else {
			if err := d.Set(consts.FieldMetadata, map[string]interface{}{}); err != nil {
				return diag.FromErr(fmt.Errorf("error setting empty metadata: %w", err))
			}
		}
	}

	return nil
}

func deleteAzureStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	rolePath := d.Id()
	_, err = client.Logical().DeleteWithContext(ctx, rolePath)
	if err != nil {
		if util.Is404(err) {
			d.SetId("")
			return nil
		}

		return diag.FromErr(fmt.Errorf("error deleting static role %q: %w", rolePath, err))
	}

	return nil
}

// NormalizeMap converts Vault map responses into the format Terraform expects.
// Vault returns metadata as map[string]string, but Terraform requires
// map[string]interface{}, so this helper normalizes the types.
func NormalizeMap(d *schema.ResourceData, key string, v interface{}) error {
	if v == nil {
		return d.Set(key, map[string]interface{}{})
	}

	switch m := v.(type) {
	case map[string]interface{}:
		return d.Set(key, m)
	case map[string]string:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			out[k] = val
		}
		return d.Set(key, out)
	case string:
		if m == "" {
			return d.Set(key, map[string]interface{}{})
		}
		var tmp map[string]interface{}
		if err := json.Unmarshal([]byte(m), &tmp); err == nil {
			return d.Set(key, tmp)
		}
		return d.Set(key, map[string]interface{}{})
	default:
		return d.Set(key, map[string]interface{}{})
	}
}

// parseAzureStaticRolePath attempts to parse out the backend and role name from the provided path.
func parseAzureStaticRolePath(path string) (backend, name string, err error) {
	ms := azureStaticRolesRegex.FindStringSubmatch(path)
	if ms == nil {
		return "", "", fmt.Errorf("no pattern match for path %s", path)
	}
	if len(ms) != 3 { // 0 = entire match, 1 = first capture group (backend), 2 = second capture group (role name)
		return "", "", fmt.Errorf("unexpected number (%d) of matches found, expected 3", len(ms))
	}

	return ms[1], ms[2], nil
}
