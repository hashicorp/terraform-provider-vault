// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var pkiSecretBackendFromConfigIssuersPathRegex = regexp.MustCompile("^(.+)/config/issuers")

const (
	fieldDefaultFollowsLatestIssuer = "default_follows_latest_issuer"
)

func pkiSecretBackendConfigIssuers() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendConfigIssuersCreateUpdate, provider.VaultVersion111),
		UpdateContext: pkiSecretBackendConfigIssuersCreateUpdate,
		DeleteContext: pkiSecretBackendConfigIssuersDelete,
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendConfigIssuersRead),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where PKI backend is mounted.",
			},
			consts.FieldDefault: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the default issuer by ID.",
			},
			fieldDefaultFollowsLatestIssuer: {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				Description: "Specifies whether a root creation or an issuer " +
					"import operation updates the default issuer to the newly added issuer.",
			},
		},
	}
}

func pkiSecretBackendConfigIssuersCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)

	path := fmt.Sprintf("%s/config/issuers", backend)

	fields := []string{
		consts.FieldDefault,
		fieldDefaultFollowsLatestIssuer,
	}

	data := map[string]interface{}{}
	for _, k := range fields {
		data[k] = d.Get(k)
	}

	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error writing data to %q, err=%s", path, err)
	}

	d.SetId(path)

	return pkiSecretBackendConfigIssuersRead(ctx, d, meta)
}

func pkiSecretBackendConfigIssuersRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	// get backend from full path
	backend, err := pkiSecretBackendFromConfigIssuersPath(path)
	if err != nil {
		return diag.FromErr(err)
	}

	// set backend and keyID
	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading %s from Vault", path)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}
	if resp == nil {
		log.Printf("[WARN] default issuer data (%s) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	fields := []string{
		consts.FieldDefault,
		fieldDefaultFollowsLatestIssuer,
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q for PKI Secret Config Issuers, err=%s",
				k, err)
		}
	}

	return nil
}

func pkiSecretBackendConfigIssuersDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendFromConfigIssuersPath(path string) (string, error) {
	if !pkiSecretBackendFromConfigIssuersPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := pkiSecretBackendFromConfigIssuersPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
