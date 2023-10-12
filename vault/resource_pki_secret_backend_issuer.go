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

var (
	pkiSecretBackendFromIssuerPathRegex = regexp.MustCompile("^(.+)/issuer/.+$")
	pkiSecretIssuerRefFromPathRegex     = regexp.MustCompile("^.+/issuer/(.+)$")
)

func pkiSecretBackendIssuerResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendIssuerCreate, provider.VaultVersion111),
		UpdateContext: pkiSecretBackendIssuerUpdate,
		DeleteContext: pkiSecretBackendIssuerDelete,
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendIssuerRead),
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
			consts.FieldIssuerRef: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Reference to an existing issuer.",
			},
			consts.FieldIssuerName: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Reference to an existing issuer.",
			},
			consts.FieldLeafNotAfterBehavior: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Behavior of a leaf's 'NotAfter' field during " +
					"issuance.",
			},
			consts.FieldManualChain: {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Chain of issuer references to build this issuer's " +
					"computed CAChain field from, when non-empty.",
			},
			consts.FieldUsage: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Comma-separated list of allowed usages for this issuer.",
			},
			consts.FieldRevocationSignatureAlgorithm: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Which signature algorithm to use when building CRLs.",
			},
			consts.FieldIssuingCertificates: {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the URL values for the Issuing Certificate field.",
			},
			consts.FieldCRLDistributionPoints: {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the URL values for the CRL Distribution Points field.",
			},
			consts.FieldOCSPServers: {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the URL values for the OCSP Servers field.",
			},
			consts.FieldEnableAIAURLTemplating: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies that the AIA URL values should be templated.",
			},
			consts.FieldIssuerID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the issuer.",
			},
		},
	}
}

// the create method does not write any data to Vault. It ensures that the provided issuer ref exists
// and that it can be tracked via TF
func pkiSecretBackendIssuerCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)
	issuerRef := d.Get(consts.FieldIssuerRef).(string)
	path := fmt.Sprintf("%s/issuer/%s", backend, issuerRef)

	// ensure given issuer ref exists before attempting to update fields
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading issuer at %s, err=%s", path, err)
	}

	if resp == nil {
		// since this resource is specifically designed to track
		// and cleanup existing issuers in Vault, we return an error
		// instead of setting ID to "" if no issuer is found
		return diag.Errorf("no issuer found at path %s", path)
	}

	d.SetId(path)

	return pkiSecretBackendIssuerUpdate(ctx, d, meta)
}

func pkiSecretBackendIssuerUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	configurableFields := []string{
		consts.FieldIssuerName,
		consts.FieldLeafNotAfterBehavior,
		consts.FieldManualChain,
		consts.FieldUsage,
		consts.FieldRevocationSignatureAlgorithm,
		consts.FieldIssuingCertificates,
		consts.FieldCRLDistributionPoints,
		consts.FieldOCSPServers,
		consts.FieldEnableAIAURLTemplating,
	}

	var patchRequired bool
	data := map[string]interface{}{}
	for _, k := range configurableFields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
			patchRequired = true
		}
	}

	// only write to Vault if a patch is required
	if patchRequired {
		_, err := client.Logical().WriteWithContext(ctx, path, data)
		if err != nil {
			return diag.Errorf("error writing data to %q, err=%s", path, err)
		}
	}

	return pkiSecretBackendIssuerRead(ctx, d, meta)
}

func pkiSecretBackendIssuerRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	// get backend from full path
	backend, err := pkiSecretBackendFromIssuerPath(path)
	if err != nil {
		return diag.FromErr(err)
	}

	issuerRef, err := pkiSecretIssuerRefFromPath(path)
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading %s from Vault", path)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if resp == nil {
		d.SetId("")
		return nil
	}

	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}

	// set backend and issuerRef
	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldIssuerRef, issuerRef); err != nil {
		return diag.FromErr(err)
	}

	fields := []string{
		consts.FieldIssuerName,
		consts.FieldLeafNotAfterBehavior,
		consts.FieldManualChain,
		consts.FieldUsage,
		consts.FieldRevocationSignatureAlgorithm,
		consts.FieldIssuingCertificates,
		consts.FieldCRLDistributionPoints,
		consts.FieldOCSPServers,
		consts.FieldEnableAIAURLTemplating,
		consts.FieldIssuerID,
	}

	for _, k := range fields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting state key %q for issuer, err=%s",
					k, err)
			}
		}
	}

	return nil
}

func pkiSecretBackendIssuerDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting PKI Issuer at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func pkiSecretBackendFromIssuerPath(path string) (string, error) {
	if !pkiSecretBackendFromIssuerPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := pkiSecretBackendFromIssuerPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func pkiSecretIssuerRefFromPath(path string) (string, error) {
	if !pkiSecretIssuerRefFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no issuer ID found")
	}
	res := pkiSecretIssuerRefFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for issuer ID", len(res))
	}
	return res[1], nil
}
