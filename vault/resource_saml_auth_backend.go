// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var (
	samlAPIFields = []string{
		consts.FieldIDPMetadataURL,
		consts.FieldIDPSSOURL,
		consts.FieldIDPEntityID,
		consts.FieldIDPCert,
		consts.FieldEntityID,
		consts.FieldACSURLs,
		consts.FieldDefaultRole,
	}
)

func samlAuthBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
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
			consts.FieldIDPMetadataURL: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The metadata URL of the identity provider.",
			},
			consts.FieldIDPSSOURL: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The SSO URL of the identity provider. Mutually " +
					"exclusive with 'idp_metadata_url'.",
			},
			consts.FieldIDPEntityID: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The entity ID of the identity provider. " +
					"Mutually exclusive with 'idp_metadata_url'.",
			},
			consts.FieldIDPCert: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The PEM encoded certificate of the identity provider. " +
					"Mutually exclusive with 'idp_metadata_url'",
			},
			consts.FieldEntityID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The entity ID of the SAML authentication service provider.",
			},
			consts.FieldACSURLs: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Required: true,
				Description: "The well-formatted URLs of your Assertion Consumer Service (ACS) " +
					"that should receive a response from the identity provider.",
			},
			consts.FieldDefaultRole: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The role to use if no role is provided during login.",
			},
			consts.FieldVerboseLogging: {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				Description: "Log additional, potentially sensitive information " +
					"during the SAML exchange according to the current logging level. Not " +
					"recommended for production.",
			},
			consts.FieldValidateAssertionSignature: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Whether to validate the assertion signature.",
			},
			consts.FieldValidateResponseSignature: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Whether to validate the response signature.",
			},
			consts.FieldTune: authMountTuneSchema(),
		},
	}, true)
}

func samlAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)

	log.Printf("[DEBUG] Enabling SAML auth backend %q", path)
	err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
		Type: consts.MountTypeSAML,
	})
	if err != nil {
		return diag.Errorf("error enabling SAML auth backend %q: %s", path, err)
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
	}

	configPath := samlAuthBackendConfigPath(path)

	data := map[string]interface{}{}

	for _, k := range samlAPIFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	// add boolean fields
	// validate_assertion_signature and validate_response_signature require Vault 1.19+
	samlBooleanFields := []string{consts.FieldVerboseLogging}
	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		samlBooleanFields = append(samlBooleanFields, consts.FieldValidateAssertionSignature, consts.FieldValidateResponseSignature)
	}

	for _, k := range samlBooleanFields {
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

	if d.HasChange(consts.FieldTune) {
		log.Printf("[DEBUG] SAML Auth '%q' tune configuration changed", path)
		if raw, ok := d.GetOk(consts.FieldTune); ok {
			log.Printf("[DEBUG] Writing SAML auth tune to '%q'", path)

			if err := authMountTune(ctx, client, "auth/"+path, raw); err != nil {
				return diag.FromErr(err)
			}

			log.Printf("[DEBUG] Written SAML auth tune to '%q'", path)
		}
	}

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

	if err := d.Set(consts.FieldPath, id); err != nil {
		return diag.FromErr(err)
	}

	samlBooleanFields := []string{consts.FieldVerboseLogging}
	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		samlBooleanFields = append(samlBooleanFields, consts.FieldValidateAssertionSignature, consts.FieldValidateResponseSignature)
	}
	// set all API fields to TF state
	fields := append(samlAPIFields, samlBooleanFields...)
	for _, k := range fields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting state key %q: err=%s", k, err)
			}
		}
	}

	log.Printf("[DEBUG] Reading saml auth tune from %q", id+"/tune")
	rawTune, err := authMountTuneGet(ctx, client, "auth/"+id)
	if err != nil {
		return diag.Errorf("error reading tune information from Vault: %s", err)
	}

	input, err := retrieveMountConfigInput(d)
	if err != nil {
		return diag.Errorf("error retrieving tune configuration from state: %s", err)
	}

	mergedTune := mergeAuthMethodTune(rawTune, input)

	if err := d.Set(consts.FieldTune, mergedTune); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path %q to state: %s", id+"/tune", err)
		return diag.FromErr(err)
	}

	return nil
}

func samlAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting SAML auth backend %q", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return diag.Errorf("error deleting SAML auth backend %q: %q", path, err)
	}
	log.Printf("[DEBUG] Deleted SAML auth backend %q", path)

	return nil
}

func samlAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}
