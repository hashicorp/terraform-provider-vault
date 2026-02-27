// Copyright IBM Corp. 2016, 2025
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
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

var pkiSecretBackendFromConfigClusterRegex = regexp.MustCompile("^(.+)/config/cluster$")

func pkiSecretBackendConfigClusterResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendConfigClusterCreate, provider.VaultVersion113),
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendConfigClusterRead),
		UpdateContext: pkiSecretBackendConfigClusterUpdate,
		DeleteContext: pkiSecretBackendConfigClusterDelete,
		Importer: &schema.ResourceImporter{
			StateContext: func(_ context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
				id := d.Id()
				if id == "" {
					return nil, fmt.Errorf("no path set for import, id=%q", id)
				}

				parts := strings.Split(mountutil.NormalizeMountPath(id), "/")
				if err := d.Set("backend", parts[0]); err != nil {
					return nil, err
				}

				return []*schema.ResourceData{d}, nil
			},
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where PKI backend is mounted.",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldPath: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the cluster's API mount path.",
			},
			consts.FieldAIAPath: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the cluster's AIA distribution point.",
			},
		},
	}
}

func pkiSecretBackendConfigClusterCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := fmt.Sprintf("%s/config/cluster", backend)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading cluster config at %s, err=%s", path, err)
	}

	if resp == nil {
		return diag.Errorf("no cluster config found at path %s", path)
	}

	d.SetId(path)

	return pkiSecretBackendConfigClusterUpdate(ctx, d, meta)
}

func pkiSecretBackendConfigClusterUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	fields := []string{
		consts.FieldPath,
		consts.FieldAIAPath,
	}

	var patchRequired bool
	data := map[string]interface{}{}
	for _, k := range fields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
			patchRequired = true
		}
	}

	if patchRequired {
		_, err := client.Logical().WriteWithContext(ctx, path, data)
		if err != nil {
			return diag.Errorf("error writing data to %q, err=%s", path, err)
		}
	}

	return pkiSecretBackendConfigClusterRead(ctx, d, meta)
}

func pkiSecretBackendConfigClusterRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	if path == "" {
		return diag.Errorf("no path set, id=%q", d.Id())
	}

	// get backend from full path
	backend, err := pkiSecretBackendFromConfigCluster(path)
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading %s from Vault", path)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	if resp == nil {
		d.SetId("")

		return nil
	}

	// set backend and issuerRef
	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	fields := []string{
		consts.FieldPath,
		consts.FieldAIAPath,
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q for cluster config, err=%s",
				k, err)
		}
	}

	return nil
}

func pkiSecretBackendConfigClusterDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendFromConfigCluster(path string) (string, error) {
	if !pkiSecretBackendFromConfigClusterRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := pkiSecretBackendFromConfigClusterRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
