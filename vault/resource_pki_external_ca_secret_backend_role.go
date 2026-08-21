// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	pkiExtCARoleFromMountPathRegex = regexp.MustCompile(`^(.+)/role/.+$`)
	pkiExtCARoleNameFromPathRegex  = regexp.MustCompile(`^.+/role/(.+)$`)
)

func pkiExternalCASecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages PKI External CA roles for certificate issuance via ACME.",
		CreateContext: pkiExternalCASecretBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(pkiExternalCASecretBackendRoleRead),
		UpdateContext: pkiExternalCASecretBackendRoleUpdate,
		DeleteContext: pkiExternalCASecretBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path where the PKI External CA secret backend is mounted.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role. Must be unique within the backend.",
			},
			consts.FieldAcmeAccountName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The ACME account to use when validating certificates.",
			},
			consts.FieldAllowedDomains: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A list of domains the role will accept certificates for. May contain identity templates.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAllowedDomainOptions: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Options influencing how allowed_domains are interpreted. Valid values: bare_domains, subdomains, wildcards, globs.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{"bare_domains", "subdomains", "wildcards", "globs"}, false),
				},
			},
			consts.FieldAllowedChallengeTypes: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The list of ACME challenge types allowed. Valid values: http-01, dns-01, tls-alpn-01.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{"http-01", "dns-01", "tls-alpn-01"}, false),
				},
			},
			consts.FieldCsrGenerateKeyType: {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "ec-256",
				Description:  "Key type to use when generating a new key for the identifier workflow. Valid values: ec-256, ec-384, ec-521, rsa-2048, rsa-4096.",
				ValidateFunc: validation.StringInSlice([]string{"ec-256", "ec-384", "ec-521", "rsa-2048", "rsa-4096"}, false),
			},
			consts.FieldCsrIdentifierPopulation: {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "cn_first",
				Description:  "Technique used to populate a CSR from identifiers. Valid values: cn_first, sans_only.",
				ValidateFunc: validation.StringInSlice([]string{"cn_first", "sans_only"}, false),
			},
			consts.FieldForce: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Force deletion even when active orders exist.",
			},
			// Computed fields returned by Vault
			consts.FieldCreationDate: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The date and time the role was created in RFC3339 format.",
			},
			consts.FieldLastUpdateDate: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The date and time the role was last updated in RFC3339 format.",
			},
		},
	}
}

func pkiExternalCASecretBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)
	path := fmt.Sprintf("%s/role/%s", mount, name)

	data := map[string]interface{}{
		consts.FieldAcmeAccountName: d.Get(consts.FieldAcmeAccountName),
	}

	listFields := []string{
		consts.FieldAllowedDomains,
		consts.FieldAllowedDomainOptions,
		consts.FieldAllowedChallengeTypes,
		consts.FieldCsrGenerateKeyType,
		consts.FieldCsrIdentifierPopulation,
	}
	for _, k := range listFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] Creating PKI External CA role at %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error creating PKI External CA role at %q: %s", path, err)
	}

	d.SetId(path)
	return pkiExternalCASecretBackendRoleRead(ctx, d, meta)
}

func pkiExternalCASecretBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	data := map[string]interface{}{}

	updateFields := []string{
		consts.FieldAcmeAccountName,
		consts.FieldAllowedDomains,
		consts.FieldAllowedDomainOptions,
		consts.FieldAllowedChallengeTypes,
		consts.FieldCsrGenerateKeyType,
		consts.FieldCsrIdentifierPopulation,
	}
	for _, k := range updateFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	if len(data) > 0 {
		log.Printf("[DEBUG] Updating PKI External CA role at %q", path)
		_, err := client.Logical().WriteWithContext(ctx, path, data)
		if err != nil {
			return diag.Errorf("error updating PKI External CA role at %q: %s", path, err)
		}
	}

	return pkiExternalCASecretBackendRoleRead(ctx, d, meta)
}

func pkiExternalCASecretBackendRoleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	mount, name, err := pkiExtCAParseRolePath(path)
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading PKI External CA role at %q", path)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading PKI External CA role at %q: %s", path, err)
	}
	if resp == nil {
		log.Printf("[WARN] PKI External CA role not found at %q, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	readFields := []string{
		consts.FieldAcmeAccountName,
		consts.FieldAllowedDomains,
		consts.FieldAllowedDomainOptions,
		consts.FieldAllowedChallengeTypes,
		consts.FieldCsrGenerateKeyType,
		consts.FieldCsrIdentifierPopulation,
		consts.FieldCreationDate,
		consts.FieldLastUpdateDate,
	}
	for _, k := range readFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting %q: %s", k, err)
			}
		}
	}

	return nil
}

func pkiExternalCASecretBackendRoleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	// append ?force=true if the force field is set
	deletePath := path
	if d.Get(consts.FieldForce).(bool) {
		deletePath = path + "?force=true"
	}

	log.Printf("[DEBUG] Deleting PKI External CA role at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, deletePath)
	if err != nil {
		return diag.Errorf("error deleting PKI External CA role at %q: %s", path, err)
	}

	return nil
}

func pkiExtCAParseRolePath(path string) (mount, name string, err error) {
	mountRes := pkiExtCARoleFromMountPathRegex.FindStringSubmatch(path)
	if len(mountRes) != 2 {
		return "", "", fmt.Errorf("could not parse mount from path %q", path)
	}
	nameRes := pkiExtCARoleNameFromPathRegex.FindStringSubmatch(path)
	if len(nameRes) != 2 {
		return "", "", fmt.Errorf("could not parse role name from path %q", path)
	}
	return mountRes[1], nameRes[1], nil
}
