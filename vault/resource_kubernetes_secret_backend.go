// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func kubernetesSecretBackendResource() *schema.Resource {
	resource := &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(kubernetesSecretBackendCreateUpdate, provider.VaultVersion111),
		ReadContext:   provider.ReadContextWrapper(kubernetesSecretBackendRead),
		UpdateContext: kubernetesSecretBackendCreateUpdate,
		DeleteContext: kubernetesSecretBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			consts.FieldKubernetesHost: {
				Type:        schema.TypeString,
				Description: "The Kubernetes API URL to connect to.",
				Optional:    true,
			},
			consts.FieldKubernetesCACert: {
				Type: schema.TypeString,
				Description: "A PEM-encoded CA certificate used by the secret engine to " +
					"verify the Kubernetes API server certificate. Defaults to the " +
					"local pod’s CA if found, or otherwise the host's root CA set.",
				Optional: true,
			},
			consts.FieldServiceAccountJWT: {
				Type: schema.TypeString,
				Description: "The JSON web token of the service account used by the " +
					"secrets engine to manage Kubernetes credentials. Defaults to the " +
					"local pod’s JWT if found.",
				Optional:      true,
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldServiceAccountJWTWO},
			},
			consts.FieldServiceAccountJWTWO: {
				Type: schema.TypeString,
				Description: "Write-only JSON web token of the service account used by the " +
					"secrets engine to manage Kubernetes credentials. This value will not be " +
					"stored in state.",
				Optional:      true,
				Sensitive:     true,
				WriteOnly:     true,
				ConflictsWith: []string{consts.FieldServiceAccountJWT},
			},
			consts.FieldServiceAccountJWTWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Version counter for write-only service account JWT.",
				RequiredWith: []string{consts.FieldServiceAccountJWTWO},
			},
			consts.FieldDisableLocalCAJWT: {
				Type: schema.TypeBool,
				Description: "Disable defaulting to the local CA certificate and service " +
					"account JWT when running in a Kubernetes pod.",
				Optional: true,
				Default:  false,
			},
		},
	}

	// Add common mount schema to the resource
	provider.MustAddSchema(resource, getMountSchema("type"))

	return resource
}

func kubernetesSecretBackendCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	var path string
	if d.IsNewResource() {
		path = d.Get(consts.FieldPath).(string)
		if err := createMount(ctx, d, meta, client, path, consts.MountTypeKubernetes); err != nil {
			return diag.FromErr(err)
		}
	} else {
		if err := updateMount(ctx, d, meta, true, false); err != nil {
			return diag.FromErr(err)
		}
		path = d.Id()
	}
	d.SetId(path)

	data := make(map[string]interface{})
	fields := []string{
		consts.FieldKubernetesCACert,
		consts.FieldDisableLocalCAJWT,
	}
	for _, k := range fields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	// Credentials are not returned by the read API, so support both a stateful
	// attribute and a write-only alternative.
	//
	// For the write-only JWT, only re-send on create or when the write-only
	// version counter changes. This avoids re-sending credentials just because
	// they're present in config.
	//
	// For the legacy (non-write-only) field, re-send when the value changes.
	shouldSendJWT := d.IsNewResource() ||
		d.HasChange(consts.FieldServiceAccountJWTWOVersion) ||
		d.HasChange(consts.FieldServiceAccountJWT)

	log.Printf("[DEBUG] JWT decision: isNewResource=%v hasChangeWOVersion=%v hasChangeJWT=%v shouldSend=%v",
		d.IsNewResource(),
		d.HasChange(consts.FieldServiceAccountJWTWOVersion),
		d.HasChange(consts.FieldServiceAccountJWT),
		shouldSendJWT)

	if shouldSendJWT {
		var jwt string
		// For write-only field, use GetRawConfigAt instead of Get
		if d.IsNewResource() || d.HasChange(consts.FieldServiceAccountJWTWOVersion) {
			p := cty.GetAttrPath(consts.FieldServiceAccountJWTWO)
			woVal, _ := d.GetRawConfigAt(p)
			if !woVal.IsNull() {
				jwt = woVal.AsString()
				log.Printf("[DEBUG] Got JWT from WO field via GetRawConfigAt: length=%d", len(jwt))
			}
		}
		if jwt == "" {
			jwt = d.Get(consts.FieldServiceAccountJWT).(string)
			log.Printf("[DEBUG] Got JWT from regular field: length=%d", len(jwt))
		}
		if jwt != "" {
			data[consts.FieldServiceAccountJWT] = jwt
			log.Printf("[DEBUG] Adding JWT to write payload: length=%d", len(jwt))
		} else {
			log.Printf("[DEBUG] JWT is empty, not adding to payload")
		}
	}

	// kubernetes_host always needs to be provided on configuration updates.
	// Otherwise, an error will occur if the KUBERNETES_SERVICE_HOST and
	// KUBERNETES_SERVICE_PORT_HTTPS environment variables aren't set.
	data[consts.FieldKubernetesHost] = d.Get(consts.FieldKubernetesHost)

	configPath := fmt.Sprintf("%s/config", path)
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return diag.Errorf(`error writing Kubernetes backend config %q, err=%s`,
			configPath, err)
	}

	return kubernetesSecretBackendRead(ctx, d, meta)
}

func kubernetesSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	resp, err := client.Logical().Read(path + "/config")
	if err != nil {
		return diag.Errorf("error reading Kubernetes backend at %s/config: err=%s",
			path, err)
	}
	if resp == nil {
		log.Printf("[WARN] Kubernetes config not found, removing from state")
		d.SetId("")
		return nil
	}

	// fieldServiceAccountJWT can't be read from the API
	// and is intentionally omitted from this list
	fields := []string{
		consts.FieldKubernetesHost,
		consts.FieldKubernetesCACert,
		consts.FieldDisableLocalCAJWT,
	}
	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q on Kubernetes backend config, err=%s",
				k, err)
		}
	}

	if err := readMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func kubernetesSecretBackendDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	if err := client.Sys().Unmount(path); err != nil {
		if util.Is404(err) {
			log.Printf("[WARN] %q not found, removing from state", path)
			d.SetId("")
		}
		return diag.Errorf("error unmounting Kubernetes backend from %q, err=%s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Kubernetes backend at %q", path)

	return nil
}
