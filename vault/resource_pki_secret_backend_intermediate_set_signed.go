// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendIntermediateSetSignedResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendIntermediateSetSignedCreate,
		Read:   ReadWrapper(pkiSecretBackendCertRead),
		Delete: pkiSecretBackendIntermediateSetSignedDelete,

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

func pkiSecretBackendIntermediateSetSignedCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)

	path := pkiSecretBackendIntermediateSetSignedCreatePath(backend)

	data := map[string]interface{}{
		"certificate": d.Get("certificate").(string),
	}

	log.Printf("[DEBUG] Creating intermediate set-signed on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating intermediate set-signed on PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created intermediate set-signed on PKI secret backend %q", backend)

	d.SetId(path)
	return pkiSecretBackendCertRead(d, meta)
}

func pkiSecretBackendIntermediateSetSignedDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendIntermediateSetSignedCreatePath(backend string) string {
	return strings.Trim(backend, "/") + "/intermediate/set-signed"
}
