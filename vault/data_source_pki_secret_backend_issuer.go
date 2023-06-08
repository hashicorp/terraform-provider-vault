// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendIssuerDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readPKISecretBackendIssuer),
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
				ForceNew:    true,
				Description: "Reference to an existing issuer.",
			},
			consts.FieldIssuerName: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the issuer.",
			},
			consts.FieldIssuerID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the issuer.",
			},
			consts.FieldKeyID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the key used by the issuer.",
			},
			consts.FieldCertificate: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate.",
			},
			consts.FieldCAChain: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The CA chain as a list of format specific certificates",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldLeafNotAfterBehavior: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Behavior of a leaf's NotAfter field during issuance.",
			},
			consts.FieldManualChain: {
				Type:     schema.TypeList,
				Computed: true,
				Description: "Chain of issuer references to build this issuer's computed " +
					"CAChain field from, when non-empty",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldUsage: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Allowed usages for this issuer.",
			},
		},
	}
}

func readPKISecretBackendIssuer(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	issuerRef := d.Get(consts.FieldIssuerRef).(string)
	path := fmt.Sprintf("%s/issuer/%s", backend, issuerRef)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", path)
	if resp == nil {
		return diag.FromErr(fmt.Errorf("no issuer found at %q", path))
	}

	d.SetId(path)

	issuerComputedFields := []string{
		consts.FieldIssuerName,
		consts.FieldIssuerID,
		consts.FieldKeyID,
		consts.FieldCertificate,
		consts.FieldCAChain,
		consts.FieldLeafNotAfterBehavior,
		consts.FieldManualChain,
		consts.FieldUsage,
	}

	for _, k := range issuerComputedFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}
