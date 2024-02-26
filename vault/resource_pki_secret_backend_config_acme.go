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
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var (
	pkiSecretBackendFromConfigACMERegex = regexp.MustCompile("^(.+)/config/acme$")
	pkiAcmeFields                       = []string{
		consts.FieldEnabled,
		consts.FieldDefaultDirectoryPolicy,
		consts.FieldAllowedRoles,
		consts.FieldAllowRoleExtKeyUsage,
		consts.FieldAllowedIssuers,
		consts.FieldEabPolicy,
		consts.FieldDnsResolver,
	}
)

func pkiSecretBackendConfigACMEResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendConfigACMECreate, provider.VaultVersion113),
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendConfigACMERead),
		UpdateContext: pkiSecretBackendConfigACMEUpdate,
		DeleteContext: pkiSecretBackendConfigACMEDelete,
		Importer: &schema.ResourceImporter{
			StateContext: func(_ context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
				id := d.Id()
				if id == "" {
					return nil, fmt.Errorf("no path set for import, id=%q", id)
				}

				parts := strings.Split(util.NormalizeMountPath(id), "/")
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
			consts.FieldEnabled: {
				Type:        schema.TypeBool,
				Required:    true,
				Description: "Specifies whether ACME is enabled.",
			},
			consts.FieldDefaultDirectoryPolicy: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the policy to be used for non-role-qualified ACME requests.",
				ValidateFunc: validation.StringMatch(
					regexp.MustCompile(`^(forbid|sign-verbatim|role:.+|external-policy(?:\:.+)?)$`), ""),
			},
			consts.FieldAllowedRoles: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Specifies which roles are allowed for use with ACME.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldAllowRoleExtKeyUsage: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies whether the ExtKeyUsage field from a role is used.",
			},
			consts.FieldAllowedIssuers: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Specifies which issuers are allowed for use with ACME.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldEabPolicy: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the policy to use for external account binding behaviour.",
				ValidateFunc: validation.StringInSlice(
					[]string{"not-required", "new-account-required", "always-required"}, false),
			},
			consts.FieldDnsResolver: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "DNS resolver to use for domain resolution on this mount. " +
					"Must be in the format <host>:<port>, with both parts mandatory.",
				ValidateFunc: validation.StringMatch(
					regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5})?$`), ""),
			},
		},
	}
}

func pkiSecretBackendConfigACMECreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := fmt.Sprintf("%s/config/acme", backend)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading acme config at %s, err=%s", path, err)
	}

	if resp == nil {
		return diag.Errorf("no acme config found at path %s", path)
	}

	d.SetId(path)

	return pkiSecretBackendConfigACMEUpdate(ctx, d, meta)
}

func pkiSecretBackendConfigACMEUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	var patchRequired bool
	data := map[string]interface{}{}
	for _, k := range pkiAcmeFields {
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

	return pkiSecretBackendConfigACMERead(ctx, d, meta)
}

func pkiSecretBackendConfigACMERead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	if path == "" {
		return diag.Errorf("no path set, id=%q", d.Id())
	}

	// get backend from full path
	backend, err := pkiSecretBackendFromConfigACME(path)
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

	for _, k := range pkiAcmeFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q for acme config, err=%s",
				k, err)
		}
	}

	return nil
}

func pkiSecretBackendConfigACMEDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendFromConfigACME(path string) (string, error) {
	if !pkiSecretBackendFromConfigACMERegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := pkiSecretBackendFromConfigACMERegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
