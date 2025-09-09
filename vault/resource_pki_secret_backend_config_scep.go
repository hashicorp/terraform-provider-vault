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
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendConfigScepResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages Vault PKI SCEP configuration",
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendConfigScepWrite, provider.VaultVersion116),
		UpdateContext: pkiSecretBackendConfigScepWrite,
		ReadContext:   pkiSecretBackendConfigScepRead,
		DeleteContext: pkiSecretBackendConfigScepDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: pkiSecretBackendConfigScepResourceSchema,
	}
}

var pkiSecretBackendConfigScepResourceSchema = map[string]*schema.Schema{
	consts.FieldBackend: {
		Type:        schema.TypeString,
		Required:    true,
		Description: "The PKI secret backend the resource belongs to",
		ForceNew:    true,
	},
	consts.FieldEnabled: {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Specifies whether SCEP is enabled",
	},
	consts.FieldDefaultPathPolicy: {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Specifies the behavior for requests using the default SCEP label. Can be sign-verbatim or a role given by role:<role_name>",
	},
	consts.FieldAllowedEncryptionAlgorithms: {
		Type:        schema.TypeList,
		Optional:    true,
		Computed:    true,
		Description: "List of allowed encryption algorithms for SCEP requests",
		Elem:        &schema.Schema{Type: schema.TypeString},
	},
	consts.FieldAllowedDigestAlgorithms: {
		Type:        schema.TypeList,
		Optional:    true,
		Computed:    true,
		Description: "List of allowed digest algorithms for SCEP requests",
		Elem:        &schema.Schema{Type: schema.TypeString},
	},
	consts.FieldRestrictCAChainToIssuer: {
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "If true, only return the issuer CA, otherwise the entire CA certificate chain will be returned if available from the PKI mount",
	},
	consts.FieldAuthenticators: {
		Type:        schema.TypeList,
		Optional:    true,
		Computed:    true,
		Description: "Lists the mount accessors SCEP should delegate authentication requests towards",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"cert": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: "The accessor and cert_role properties for cert auth backends",
				},
				"scep": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: "The accessor property for SCEP auth backends",
				},
			},
		},
		MaxItems: 1,
	},
	consts.FieldExternalValidation: {
		Type:        schema.TypeList,
		Optional:    true,
		Computed:    true,
		Description: "Lists the 3rd party validation of SCEP requests",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"intune": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: "The credentials to enable Microsoft Intune validation of SCEP requests",
					DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
						isClientSecret := strings.HasSuffix(k, "client_secret")
						return isClientSecret
					},
				},
			},
		},
	},
	consts.FieldLogLevel: {
		Type:        schema.TypeString,
		Optional:    true,
		Computed:    true,
		Description: "The level of logging verbosity, affects only SCEP logs on this mount",
	},
	consts.FieldLastUpdated: {
		Type:        schema.TypeString,
		Computed:    true, // read-only property
		Description: "A read-only timestamp representing the last time the configuration was updated",
	},
}

func pkiSecretBackendConfigScepWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyPkiScepFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendConfigScepPath(backend)

	data := map[string]interface{}{}
	for field, fieldSchema := range pkiSecretBackendConfigScepResourceSchema {
		switch field {
		case consts.FieldBackend, consts.FieldLastUpdated, consts.FieldNamespace:
			continue
		case consts.FieldAuthenticators, consts.FieldExternalValidation:
			if value, ok := getListOfNotEmptyMaps(d, field); ok {
				data[field] = value
			}
		default:
			if fieldSchema.Type == schema.TypeBool {
				data[field] = d.Get(field)
			} else {
				if value, ok := d.GetOkExists(field); ok {
					data[field] = value
				}
			}
		}
	}

	log.Printf("[DEBUG] Updating SCEP config on PKI secret backend %q:\n%v", backend, data)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error updating SCEP config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Updated SCEP config on PKI secret backend %q", backend)

	d.SetId(path)

	return pkiSecretBackendConfigScepRead(ctx, d, meta)
}

// getListOfNotEmptyMaps is for fields of TypeList whose elements are of TypeMap. It expects there to be
// at most one map, and the entries of this map are expected be other maps. It returns the map, but it
// removes any entries whose value are empty.
func getListOfNotEmptyMaps(d *schema.ResourceData, field string) (map[string]any, bool) {
	raw, ok := d.GetOk(field)
	if !ok {
		return nil, false
	}
	listOfMaps := raw.([]any)
	if len(listOfMaps) == 0 {
		return nil, false
	}
	mapOfMaps, ok := listOfMaps[0].(map[string]any)
	if !ok {
		return nil, false
	}
	for k, v := range mapOfMaps {
		if len(v.(map[string]any)) == 0 {
			delete(mapOfMaps, k)
		}
	}
	return mapOfMaps, true
}

func pkiSecretBackendConfigScepRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	id := d.Id()
	if id == "" {
		return diag.FromErr(fmt.Errorf("no path set for import, id=%q", id))
	}

	backend := strings.TrimSuffix(id, "/config/scep")
	if err := d.Set("backend", backend); err != nil {
		return diag.FromErr(fmt.Errorf("failed setting field [%s] with value [%v]: %w", "backend", backend, err))
	}

	if err := verifyPkiScepFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed getting client: %w", err))
	}

	if err := readScepConfig(ctx, d, client, id); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func pkiSecretBackendConfigScepDelete(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	// There isn't any delete API for the SCEP config.
	return nil
}
