// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendIntermediateSetSignedResource() *schema.Resource {
	return &schema.Resource{
<<<<<<< HEAD
		CreateContext: pkiSecretBackendIntermediateSetSignedCreate,
		ReadContext:   ReadContextWrapper(pkiSecretBackendCertRead),
		DeleteContext: pkiSecretBackendIntermediateSetSignedDelete,
=======
		Create: pkiSecretBackendIntermediateSetSignedCreate,
		Read:   provider.ReadWrapper(pkiSecretBackendCertRead),
		Delete: pkiSecretBackendIntermediateSetSignedDelete,
>>>>>>> main

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PKI secret backend the resource belongs to.",
				ForceNew:    true,
			},
			"certificate": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The certificate.",
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

	backend := d.Get("backend").(string)

	path := pkiSecretBackendIntermediateSetSignedCreatePath(backend)

	data := map[string]interface{}{
		"certificate": d.Get("certificate").(string),
	}

	log.Printf("[DEBUG] Creating intermediate set-signed on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error creating intermediate set-signed on PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created intermediate set-signed on PKI secret backend %q", backend)

	d.SetId(path)
	return pkiSecretBackendCertRead(ctx, d, meta)
}

func pkiSecretBackendIntermediateSetSignedDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendIntermediateSetSignedCreatePath(backend string) string {
	return strings.Trim(backend, "/") + "/intermediate/set-signed"
}
