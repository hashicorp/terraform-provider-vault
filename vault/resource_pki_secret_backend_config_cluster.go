// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var pkiClusterFields = []string{
	consts.FieldPath,
	consts.FieldAIAPath,
}

func pkiSecretBackendConfigClusterResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendConfigClusterCreateUpdate,
		Read:   provider.ReadWrapper(pkiSecretBackendConfigClusterRead),
		Update: pkiSecretBackendConfigClusterCreateUpdate,
		Delete: pkiSecretBackendConfigClusterDelete,
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
				Description: "The path of the PKI secret backend the resource belongs to.",
			},
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the path to this performance replication cluster's API mount path.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldAIAPath: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the path to this performance replication cluster's AIA distribution point.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func pkiSecretBackendConfigClusterCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)

	path := pkiSecretBackendConfigClusterPath(backend)

	action := "Create"
	if !d.IsNewResource() {
		action = "Update"
	}

	data := map[string]interface{}{}

	for _, k := range pkiClusterFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	log.Printf("[DEBUG] %s cluster config on PKI secret backend %q", action, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing PKI cluster config to %q: %w", backend, err)
	}
	log.Printf("[DEBUG] %sd cluster config on PKI secret backend %q", action, backend)

	if d.IsNewResource() {
		d.SetId(fmt.Sprintf("%s/config/cluster", backend))
	}

	return pkiSecretBackendConfigClusterRead(d, meta)
}

func pkiSecretBackendConfigClusterRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	if path == "" {
		return fmt.Errorf("no path set, id=%q", d.Id())
	}

	log.Printf("[DEBUG] Reading cluster config from PKI secret path %q", path)
	config, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading cluster config on PKI secret backend %q: %s", path, err)
	}

	if config == nil {
		log.Printf("[WARN] Removing cluster config path %q as its ID is invalid", path)
		d.SetId("")
		return nil
	}

	for _, k := range pkiClusterFields {
		d.Set(k, config.Data[k])
	}

	return nil
}

func pkiSecretBackendConfigClusterDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendConfigClusterPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/cluster"
}
