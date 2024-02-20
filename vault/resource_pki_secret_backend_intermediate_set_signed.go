// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendIntermediateSetSignedResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendIntermediateSetSignedCreate,
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendCertRead),
		DeleteContext: pkiSecretBackendIntermediateSetSignedDelete,
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			consts.FieldCertificate: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The certificate.",
				ForceNew:    true,
			},
			consts.FieldImportedIssuers: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed:    true,
				Description: "The imported issuers.",
				ForceNew:    true,
			},
			consts.FieldImportedKeys: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed:    true,
				Description: "The imported keys.",
				ForceNew:    true,
			},
		},
	}
}

func pkiSecretBackendIntermediateSetSignedCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)

	path := pkiSecretBackendIntermediateSetSignedCreatePath(backend)

	data := map[string]interface{}{
		consts.FieldCertificate: d.Get(consts.FieldCertificate).(string),
	}

	log.Printf("[DEBUG] Creating intermediate set-signed on PKI secret backend %q", backend)
	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating intermediate set-signed on PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created intermediate set-signed on PKI secret backend %q", backend)

	id := path
	if provider.IsAPISupported(meta, provider.VaultVersion111) {
		// multiple set-signed calls can be made
		// ensure unique IDs
		uniqueSuffix := uuid.New()
		id = fmt.Sprintf("%s/%s", path, uniqueSuffix)
	}
	d.SetId(id)

	computedIssuerFields := []string{consts.FieldImportedIssuers, consts.FieldImportedKeys}

	for _, k := range computedIssuerFields {
		// Vault versions <= 1.10 do not return any response for this endpoint
		// Set computed fields to nil to avoid drift
		if resp == nil {
			if err := d.Set(k, nil); err != nil {
				return diag.FromErr(err)
			}
		} else {
			// If response is obtained, multi-issuer fields are present in data
			if v, ok := resp.Data[k]; ok {
				if err := d.Set(k, v); err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}

	return pkiSecretBackendCertRead(ctx, d, meta)
}

func pkiSecretBackendIntermediateSetSignedDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendIntermediateSetSignedCreatePath(backend string) string {
	return strings.Trim(backend, "/") + "/intermediate/set-signed"
}
