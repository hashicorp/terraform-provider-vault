// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/util"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func consulSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: consulSecretBackendCreate,
		ReadContext:   ReadContextWrapper(consulSecretBackendRead),
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
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the Consul token to use when managing or issuing new tokens.",
				Sensitive:   true,
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
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Client key used for Consul's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_cert.",
				Sensitive:   true,
			},
			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Default:     false,
				Description: "Specifies if the secret backend is local only",
			},
		},
	})
}

func consulSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get("path").(string)
	address := d.Get("address").(string)
	scheme := d.Get("scheme").(string)
	token := d.Get("token").(string)
	caCert := d.Get("ca_cert").(string)
	clientCert := d.Get("client_cert").(string)
	clientKey := d.Get("client_key").(string)
	local := d.Get("local").(bool)

	configPath := consulSecretBackendConfigPath(path)

	info := &api.MountInput{
		Type:        consts.MountTypeConsul,
		Description: d.Get("description").(string),
		Local:       local,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		},
	}

	log.Printf("[DEBUG] Mounting Consul backend at %q", path)

	// If a token isn't provided and the Vault version is less than 1.11, fail before
	// mounting the path in Vault.
	useAPIVer1 := provider.IsAPISupported(meta, provider.VaultVersion111)

	if token == "" && !useAPIVer1 {
		return diag.Errorf(`error writing Consul configuration: no token provided and the 
Vault client version does not meet the minimum requirement for this feature (Vault 1.11+)`)
	}

	if err := client.Sys().Mount(path, info); err != nil {
		return diag.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted Consul backend at %q", path)

	log.Printf("[DEBUG] Writing Consul configuration to %q", configPath)
	data := map[string]interface{}{
		"address":     address,
		"scheme":      scheme,
		"ca_cert":     caCert,
		"client_cert": clientCert,
		"client_key":  clientKey,
	}
	if token != "" {
		data["token"] = token
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

func consulSecretBackendRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	configPath := consulSecretBackendConfigPath(path)

	log.Printf("[DEBUG] Reading Consul backend mount %q from Vault", path)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return diag.Errorf("error reading mount %q: %s", path, err)
	}

	// path can have a trailing slash, but doesn't need to have one
	// this standardises on having a trailing slash, which is how the
	// API always responds.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Reading %s from Vault", configPath)
	secret, err := client.Logical().Read(configPath)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	d.Set("path", path)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)
	d.Set("local", mount.Local)

	// token, sadly, we can't read out
	// the API doesn't support it
	// So... if it drifts, it drift.
	d.Set("address", secret.Data["address"].(string))
	d.Set("scheme", secret.Data["scheme"].(string))

	return nil
}

func consulSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	configPath := consulSecretBackendConfigPath(path)

	path, err := util.Remount(d, client, consts.FieldPath, false)
	if err != nil {
		return diag.FromErr(err)
	}

	if d.HasChange("default_lease_ttl_seconds") || d.HasChange("max_lease_ttl_seconds") {
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		}

		log.Printf("[DEBUG] Updating lease TTLs for %q", path)
		if err := client.Sys().TuneMount(path, config); err != nil {
			return diag.Errorf("error updating mount TTLs for %q: %s", path, err)
		}

	}
	if d.HasChange("address") || d.HasChange("token") || d.HasChange("scheme") ||
		d.HasChange("ca_cert") || d.HasChange("client_cert") || d.HasChange("client_key") {
		log.Printf("[DEBUG] Updating Consul configuration at %q", configPath)
		data := map[string]interface{}{
			"address":     d.Get("address").(string),
			"token":       d.Get("token").(string),
			"scheme":      d.Get("scheme").(string),
			"ca_cert":     d.Get("ca_cert").(string),
			"client_cert": d.Get("client_cert").(string),
			"client_key":  d.Get("client_key").(string),
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
	newToken := diff.Get("token").(string)
	isTokenValueKnown := diff.NewValueKnown("token")

	// Disallow the following:
	//   1. Bootstrap is true and the token field is set to something.
	//   2. Bootstrap is true and the token field is empty, but we don't know the final value of token.
	//   3. Bootstrap is false, the token field is empty, and we know this is the final value of token.
	if newBootstrap := diff.Get("bootstrap").(bool); newBootstrap {
		if newToken != "" ||
			(newToken == "" && !isTokenValueKnown) {
			return fmt.Errorf("field 'bootstrap' must be set to false when 'token' is specified")
		}
	} else {
		if newToken == "" && isTokenValueKnown {
			return fmt.Errorf("field 'bootstrap' must be set to true when 'token' is unspecified")
		}
	}

	// check whether mount migration is required
	f := getMountCustomizeDiffFunc(consts.FieldPath)
	return f(ctx, diff, meta)
}
