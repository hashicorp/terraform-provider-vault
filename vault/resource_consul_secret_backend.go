// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func consulSecretBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: consulSecretBackendCreate,
		ReadContext:   provider.ReadContextWrapper(consulSecretBackendRead),
		UpdateContext: consulSecretBackendUpdate,
		DeleteContext: consulSecretBackendDelete,
		CustomizeDiff: consulSecretsBackendCustomizeDiff,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     consts.MountTypeConsul,
				Description: "Unique name of the Vault Consul mount to configure",
				StateFunc: func(s interface{}) string {
					return strings.Trim(s.(string), "/")
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
				Description: "Default lease duration for secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
				Description: "Maximum possible lease duration for secrets in seconds",
			},
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the address of the Consul instance, provided as \"host:port\" like \"127.0.0.1:8500\".",
			},
			"scheme": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "http",
				Description: "Specifies the URL scheme to use. Defaults to \"http\".",
			},
			"token": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Specifies the Consul token to use when managing or issuing new tokens. " +
					"Mutually exclusive with 'token_wo'.",
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldTokenWO},
			},
			consts.FieldTokenWO: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Specifies the Consul token to use when managing or issuing new tokens. This field is write-only and will never be stored in state. " +
					"Mutually exclusive with 'token'. Requires 'token_wo_version' to trigger updates.",
				Sensitive:     true,
				WriteOnly:     true,
				ConflictsWith: []string{consts.FieldToken},
			},
			consts.FieldTokenWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Version counter for the write-only token. Increment this value to trigger rotation of the token. Required when using 'token_wo'.",
				RequiredWith: []string{consts.FieldTokenWO},
			},
			"bootstrap": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Denotes a backend resource that is used to bootstrap the Consul ACL system. Only one resource may be used to bootstrap.",
				Default:     false,
			},
			"ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "CA certificate to use when verifying Consul server certificate, must be x509 PEM encoded.",
				Sensitive:   false,
			},
			"client_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Client certificate used for Consul's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_key.",
				Sensitive:   true,
			},
			"client_key": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "",
				Description: "Client key used for Consul's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_cert. " +
					"Mutually exclusive with 'client_key_wo'.",
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldClientKeyWO},
			},
			consts.FieldClientKeyWO: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Client key used for Consul's TLS communication, must be x509 PEM encoded. This field is write-only and will never be stored in state. " +
					"Mutually exclusive with 'client_key'. Requires 'client_key_wo_version' to trigger updates.",
				Sensitive:     true,
				WriteOnly:     true,
				ConflictsWith: []string{consts.FieldClientKey},
			},
			consts.FieldClientKeyWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Version counter for the write-only client key. Increment this value to trigger rotation of the client key. Required when using 'client_key_wo'.",
				RequiredWith: []string{consts.FieldClientKeyWO},
			},
			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Default:     false,
				Description: "Specifies if the secret backend is local only",
			},
		},
	}, false)

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
		consts.FieldDefaultLeaseTTLSeconds,
		consts.FieldMaxLeaseTTLSeconds,
		consts.FieldLocal,
	))

	return r
}

// getWriteOnlyOrLegacyValue extracts a field value from either write-only or legacy field.
// It prioritizes write-only fields when the version field is present and has changed (or is new resource).
// Falls back to legacy field if write-only is not being used.
func getWriteOnlyOrLegacyValue(d *schema.ResourceData, woField, woVersionField, legacyField string, isNewOrVersionChanged bool) string {
	var value string

	// Check if using write-only field
	if isNewOrVersionChanged {
		if _, ok := d.GetOk(woVersionField); ok {
			// Using write-only field - get from raw config
			p := cty.GetAttrPath(woField)
			woVal, _ := d.GetRawConfigAt(p)
			if !woVal.IsNull() {
				value = woVal.AsString()
			}
		}
	}

	// Fall back to legacy field if not using write-only
	if value == "" {
		if v, ok := d.GetOk(legacyField); ok {
			value = v.(string)
		}
	}

	return value
}

func consulSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get("path").(string)
	address := d.Get("address").(string)
	scheme := d.Get("scheme").(string)
	caCert := d.Get("ca_cert").(string)
	clientCert := d.Get("client_cert").(string)

	// Handle token: legacy field or write-only field
	// Only send the token on create or when the write-only version changes
	token := getWriteOnlyOrLegacyValue(d, consts.FieldTokenWO, consts.FieldTokenWOVersion, consts.FieldToken, d.IsNewResource() || d.HasChange(consts.FieldTokenWOVersion))

	// Handle client_key: legacy field or write-only field
	// Only send the client_key on create or when the write-only version changes
	clientKey := getWriteOnlyOrLegacyValue(d, consts.FieldClientKeyWO, consts.FieldClientKeyWOVersion, consts.FieldClientKey, d.IsNewResource() || d.HasChange(consts.FieldClientKeyWOVersion))

	configPath := consulSecretBackendConfigPath(path)

	log.Printf("[DEBUG] Mounting Consul backend at %q", path)

	if err := createMount(ctx, d, meta, client, path, consts.MountTypeConsul); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Mounted Consul backend at %q", path)
	// If a token isn't provided and the Vault version is less than 1.11, fail before
	// mounting the path in Vault.
	useAPIVer1 := provider.IsAPISupported(meta, provider.VaultVersion111)

	if token == "" && !useAPIVer1 {
		return diag.Errorf(`error writing Consul configuration: no token provided and the 
Vault client version does not meet the minimum requirement for this feature (Vault 1.11+)`)
	}

	log.Printf("[DEBUG] Writing Consul configuration to %q", configPath)
	data := map[string]interface{}{
		"address":     address,
		"scheme":      scheme,
		"ca_cert":     caCert,
		"client_cert": clientCert,
	}

	// Only add token to data if we have a value
	if token != "" {
		data["token"] = token
	}

	// Only add client_key to data if we have a value
	if clientKey != "" {
		data["client_key"] = clientKey
	}

	if _, err := client.Logical().Write(configPath, data); err != nil {
		// the mount was created, but we failed to configure it for some reason,
		// we need to roll that back
		if err := client.Sys().Unmount(path); err != nil {
			return diag.Errorf("failed to unmount %q, after encountering a "+
				"fatal configuration error, the mount may still persist in vault", path)
		}
		return diag.Errorf("error writing Consul configuration to %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Wrote Consul configuration to %q", configPath)

	d.SetId(path)

	return consulSecretBackendRead(ctx, d, meta)
}

func consulSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	configPath := consulSecretBackendConfigPath(path)

	log.Printf("[DEBUG] Reading %s from Vault", configPath)
	secret, err := client.Logical().Read(configPath)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	if err := d.Set("path", path); err != nil {
		return diag.FromErr(err)
	}
	if err := readMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("address", secret.Data["address"].(string)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("scheme", secret.Data["scheme"].(string)); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func consulSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if err := updateMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	configPath := consulSecretBackendConfigPath(path)

	if d.HasChange("address") || d.HasChange("token") || d.HasChange(consts.FieldTokenWOVersion) ||
		d.HasChange("scheme") || d.HasChange("ca_cert") || d.HasChange("client_cert") ||
		d.HasChange("client_key") || d.HasChange(consts.FieldClientKeyWOVersion) {
		log.Printf("[DEBUG] Updating Consul configuration at %q", configPath)

		token := getWriteOnlyOrLegacyValue(d, consts.FieldTokenWO, consts.FieldTokenWOVersion, consts.FieldToken, d.HasChange(consts.FieldTokenWOVersion))

		clientKey := getWriteOnlyOrLegacyValue(d, consts.FieldClientKeyWO, consts.FieldClientKeyWOVersion, consts.FieldClientKey, d.HasChange(consts.FieldClientKeyWOVersion))

		data := map[string]interface{}{
			"address":     d.Get("address").(string),
			"scheme":      d.Get("scheme").(string),
			"ca_cert":     d.Get("ca_cert").(string),
			"client_cert": d.Get("client_cert").(string),
		}

		// Only add token to data if we have a value
		if token != "" {
			data["token"] = token
		}

		// Only add client_key to data if we have a value
		if clientKey != "" {
			data["client_key"] = clientKey
		}

		if _, err := client.Logical().Write(configPath, data); err != nil {
			return diag.Errorf("error configuring Consul configuration for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated Consul configuration at %q", configPath)
	}

	return consulSecretBackendRead(ctx, d, meta)
}

func consulSecretBackendDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Consul backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return diag.Errorf("error unmounting Consul backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Consul backend %q", path)
	return nil
}

func consulSecretBackendConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/access"
}

func consulSecretsBackendCustomizeDiff(ctx context.Context, diff *schema.ResourceDiff, meta interface{}) error {
	// Check both legacy token and write-only token
	newToken := diff.Get("token").(string)
	isTokenValueKnown := diff.NewValueKnown("token")

	// Check if using write-only token
	newTokenWO := diff.Get(consts.FieldTokenWO).(string)
	isTokenWOValueKnown := diff.NewValueKnown(consts.FieldTokenWO)

	// Determine if any token is provided (legacy or write-only)
	hasToken := newToken != "" || newTokenWO != ""
	isAnyTokenKnown := isTokenValueKnown || isTokenWOValueKnown

	// Disallow the following:
	//   1. Bootstrap is true and any token field is set to something.
	//   2. Bootstrap is true and no token field is set, but we don't know the final value.
	//   3. Bootstrap is false, no token field is set, and we know this is the final value.
	if newBootstrap := diff.Get("bootstrap").(bool); newBootstrap {
		if hasToken ||
			(!hasToken && !isAnyTokenKnown) {
			return fmt.Errorf("field 'bootstrap' must be set to false when 'token' or 'token_wo' is specified")
		}
	} else {
		if !hasToken && isAnyTokenKnown {
			return fmt.Errorf("field 'bootstrap' must be set to true when neither 'token' nor 'token_wo' is specified")
		}
	}

	// check whether mount migration is required
	f := getMountCustomizeDiffFunc(consts.FieldPath)
	return f(ctx, diff, meta)
}
