// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func pkiSecretBackendConfigUrlsResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendConfigUrlsCreateUpdate,
		Read:   provider.ReadWrapper(pkiSecretBackendConfigUrlsRead),
		Update: pkiSecretBackendConfigUrlsCreateUpdate,
		Delete: pkiSecretBackendConfigUrlsDelete,
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
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path of the PKI secret backend the resource belongs to.",
			},
			"issuing_certificates": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies the URL values for the Issuing Certificate field.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"crl_distribution_points": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies the URL values for the CRL Distribution Points field.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"ocsp_servers": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies the URL values for the OCSP Servers field.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func pkiSecretBackendConfigUrlsCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)

	path := pkiSecretBackendConfigUrlsPath(backend)

	action := "Create"
	if !d.IsNewResource() {
		action = "Update"
	}

	data := map[string]interface{}{
		"issuing_certificates":    d.Get("issuing_certificates"),
		"crl_distribution_points": d.Get("crl_distribution_points"),
		"ocsp_servers":            d.Get("ocsp_servers"),
	}

	log.Printf("[DEBUG] %s URL config on PKI secret backend %q", action, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing PKI URL config to %q: %w", backend, err)
	}
	log.Printf("[DEBUG] %sd URL config on PKI secret backend %q", action, backend)

	if d.IsNewResource() {
		d.SetId(fmt.Sprintf("%s/config/urls", backend))
	}

	return pkiSecretBackendConfigUrlsRead(d, meta)
}

func pkiSecretBackendConfigUrlsRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	if path == "" {
		return fmt.Errorf("no path set, id=%q", d.Id())
	}

	log.Printf("[DEBUG] Reading URL config from PKI secret path %q", path)
	config, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading URL config on PKI secret backend %q: %s", path, err)
	}

	if config == nil {
		log.Printf("[WARN] Removing URL config path %q as its ID is invalid", path)
		d.SetId("")
		return nil
	}

	fields := []string{
		"issuing_certificates",
		"crl_distribution_points",
		"ocsp_servers",
	}
	for _, k := range fields {
		if err := d.Set(k, config.Data[k]); err != nil {
			return err
		}
	}

	return nil
}

func pkiSecretBackendConfigUrlsDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendConfigUrlsPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/urls"
}
