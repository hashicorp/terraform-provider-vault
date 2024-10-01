// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	fieldIDPMetadataURL = "idp_metadata_url"
	fieldIDPSSOURL      = "idp_sso_url"
	fieldIDPEntityID    = "idp_entity_id"
	fieldIDPCert        = "idp_cert"
	fieldEntityID       = "entity_id"
	fieldACSURLS        = "acs_urls"
	fieldDefaultRole    = "default_role"
	fieldVerboseLogging = "verbose_logging"
)

var (
	samlAPIFields = []string{
		fieldIDPMetadataURL,
		fieldIDPSSOURL,
		fieldIDPEntityID,
		fieldIDPCert,
		fieldEntityID,
		fieldACSURLS,
		fieldDefaultRole,
	}

	samlBooleanAPIFields = []string{
		fieldVerboseLogging,
	}
)

func samlAuthBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(samlAuthBackendWrite, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(samlAuthBackendRead),
		UpdateContext: samlAuthBackendUpdate,
		DeleteContext: samlAuthBackendDelete,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "saml",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			fieldIDPMetadataURL: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The metadata URL of the identity provider.",
			},
			fieldIDPSSOURL: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The SSO URL of the identity provider. Mutually " +
					"exclusive with 'idp_metadata_url'.",
			},
			fieldIDPEntityID: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The entity ID of the identity provider. " +
					"Mutually exclusive with 'idp_metadata_url'.",
			},
			fieldIDPCert: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The PEM encoded certificate of the identity provider. " +
					"Mutually exclusive with 'idp_metadata_url'",
			},
			fieldEntityID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The entity ID of the SAML authentication service provider.",
			},
			fieldACSURLS: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Required: true,
				Description: "The well-formatted URLs of your Assertion Consumer Service (ACS) " +
					"that should receive a response from the identity provider.",
			},
			fieldDefaultRole: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The role to use if no role is provided during login.",
			},
			fieldVerboseLogging: {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				Description: "Log additional, potentially sensitive information " +
					"during the SAML exchange according to the current logging level. Not " +
					"recommended for production.",
			},
		},
	}, true)

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getAuthMountSchema(
		consts.FieldPath,
		consts.FieldType,
	))

	return r
}

func samlAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)

	log.Printf("[DEBUG] Enabling SAML auth backend %q", path)
	if err := createAuthMount(ctx, d, meta, client, path, consts.MountTypeSAML); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Enabled SAML auth backend %q", path)

	// set ID to where engine is mounted
	d.SetId(path)

	return samlAuthBackendUpdate(ctx, d, meta)
}

func samlAuthBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	if !d.IsNewResource() {
		newMount, err := util.Remount(d, client, consts.FieldPath, true)
		if err != nil {
			return diag.FromErr(err)
		}

		path = newMount

		// tune auth mount if needed
		if err := updateAuthMount(ctx, d, meta, true); err != nil {
			return diag.FromErr(err)
		}
	}

	configPath := samlAuthBackendConfigPath(path)

	data := map[string]interface{}{}

	for _, k := range samlAPIFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	// add boolean fields
	for _, k := range samlBooleanAPIFields {
		data[k] = d.Get(k)
	}
	log.Printf("[DEBUG] Writing saml auth backend config to %q", configPath)
	_, err := client.Logical().Write(configPath, data)
	if err != nil {
		return diag.Errorf("error writing to %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Wrote saml auth backend config to %q", configPath)

	// set ID to where engine is mounted
	d.SetId(path)

	return samlAuthBackendRead(ctx, d, meta)
}

func samlAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	id := d.Id()
	log.Printf("[DEBUG] Reading saml auth backend config")
	resp, err := client.Logical().Read(samlAuthBackendConfigPath(id))
	if err != nil {
		return diag.Errorf("error reading saml auth backend config from %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read saml auth backend config")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", id)
		d.SetId("")
		return nil
	}

	if err := readAuthMount(ctx, d, meta, true); err != nil {
		return diag.FromErr(err)
	}

	// set all API fields to TF state
	fields := append(samlAPIFields, samlBooleanAPIFields...)
	for _, k := range fields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting state key %q: err=%s", k, err)
			}
		}
	}

	return nil
}

func samlAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	return authMountDisable(ctx, client, d.Id())
}

func samlAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}
