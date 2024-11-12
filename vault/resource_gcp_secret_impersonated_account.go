// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	gcpSecretImpersonatedAccountBackendFromPathRegex = regexp.MustCompile("^(.+)/impersonated-account/.+$")
	gcpSecretImpersonatedAccountNameFromPathRegex    = regexp.MustCompile("^.+/impersonated-account/(.+)$")
)

func gcpSecretImpersonatedAccountResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: gcpSecretImpersonatedAccountCreate,
		ReadContext:   provider.ReadContextWrapper(gcpSecretImpersonatedAccountRead),
		UpdateContext: gcpSecretImpersonatedAccountUpdate,
		DeleteContext: gcpSecretImpersonatedAccountDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path where the GCP secrets engine is mounted.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldImpersonatedAccount: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the Impersonated Account to create",
				ForceNew:    true,
			},
			consts.FieldServiceAccountEmail: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Email of the GCP service account.",
			},
			consts.FieldTokenScopes: {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:    true,
				Description: "List of OAuth scopes to assign to `access_token` secrets generated under this impersonated account (`access_token` impersonated accounts only) ",
			},
			consts.FieldServiceAccountProject: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Project of the GCP Service Account managed by this impersonated account",
			},
			consts.FieldTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Time to live.",
				Computed:    true,
			},
		},
	}
}

func gcpSecretImpersonatedAccountCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	impersonatedAccount := d.Get(consts.FieldImpersonatedAccount).(string)

	path := gcpSecretImpersonatedAccountPath(backend, impersonatedAccount)

	log.Printf("[DEBUG] Writing GCP Secrets backend impersonated account %q", path)

	data := map[string]interface{}{}
	gcpSecretImpersonatedAccountUpdateFields(d, data)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("error writing GCP Secrets backend impersonated account %q: %s", path, err)
	}
	d.SetId(path)
	log.Printf("[DEBUG] Wrote GCP Secrets backend impersonated account %q", path)

	return gcpSecretImpersonatedAccountRead(ctx, d, meta)
}

func gcpSecretImpersonatedAccountRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()

	backend, err := gcpSecretImpersonatedAccountBackendFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for GCP secrets backend impersonated account: %s", path, err)
	}

	impersonatedAccount, err := gcpSecretImpersonatedAccountNameFromPath(path)
	if err != nil {
		return diag.Errorf("invalid path %q for GCP Secrets backend impersonated account: %s", path, err)
	}

	log.Printf("[DEBUG] Reading GCP Secrets backend impersonated account %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading GCP Secrets backend impersonated account %q: %s", path, err)
	}

	log.Printf("[DEBUG] Read GCP Secrets backend impersonated account %q", path)
	if resp == nil {
		log.Printf("[WARN] GCP Secrets backend impersonated account %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldImpersonatedAccount, impersonatedAccount); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range []string{consts.FieldTokenScopes, consts.FieldServiceAccountEmail, consts.FieldServiceAccountProject, consts.FieldTTL} {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for GCP Secrets backend impersonated account %q: %q", k, path, err)
			}
		}
	}

	return nil
}

func gcpSecretImpersonatedAccountUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()

	data := map[string]interface{}{}
	gcpSecretImpersonatedAccountUpdateFields(d, data)

	log.Printf("[DEBUG] Updating GCP Secrets backend impersonated account %q", path)

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating GCP Secrets backend impersonated account %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated GCP Secrets backend impersonated account %q", path)

	return gcpSecretImpersonatedAccountRead(ctx, d, meta)
}

func gcpSecretImpersonatedAccountDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting GCP secrets backend impersonated account %q", path)
	_, err = client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting GCP secrets backend impersonated account %q", path)
	}
	log.Printf("[DEBUG] Deleted GCP secrets backend impersonated account %q", path)

	return nil
}

func gcpSecretImpersonatedAccountUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	if v, ok := d.GetOk(consts.FieldServiceAccountEmail); ok {
		data[consts.FieldServiceAccountEmail] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldServiceAccountProject); ok {
		data[consts.FieldServiceAccountProject] = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldTokenScopes); ok {
		data[consts.FieldTokenScopes] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk(consts.FieldTTL); ok {
		data[consts.FieldTTL] = v.(string)
	}
}

func gcpSecretImpersonatedAccountPath(backend, impersonatedAccount string) string {
	return strings.Trim(backend, "/") + "/impersonated-account/" + strings.Trim(impersonatedAccount, "/")
}

func gcpSecretImpersonatedAccountBackendFromPath(path string) (string, error) {
	if !gcpSecretImpersonatedAccountBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := gcpSecretImpersonatedAccountBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func gcpSecretImpersonatedAccountNameFromPath(path string) (string, error) {
	if !gcpSecretImpersonatedAccountNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no impersonated account found")
	}
	res := gcpSecretImpersonatedAccountNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}
