// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var errKMIPScopeNotFound = errors.New("KMIP scope not found")

func kmipSecretScopeResource() *schema.Resource {
	return &schema.Resource{
		Create: kmipSecretScopeCreate,
		Read:   provider.ReadWrapper(kmipSecretScopeRead),
		Update: kmipSecretScopeUpdate,
		Delete: kmipSecretScopeDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where KMIP backend is mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			"scope": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the scope",
			},
			"force": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Force deletion even if there are managed objects in the scope",
			},
		},
	}
}

func kmipSecretScopeCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	scope := d.Get("scope").(string)
	force := d.Get("force").(bool)

	data := map[string]interface{}{
		"scope": scope,
		"force": force,
	}

	scopePath := getKMIPScopePath(d)
	log.Printf("[DEBUG] Updating %q", scopePath)
	if _, err := client.Logical().Write(scopePath, data); err != nil {
		return fmt.Errorf("error updating KMIP scope %s: %s", scopePath, err)
	}
	d.SetId(scopePath)
	if err := d.Set("scope", scope); err != nil {
		return err
	}

	return kmipSecretScopeRead(d, meta)
}

func kmipSecretScopeRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	scopeListPath := d.Get("path").(string) + "/scope"
	scope := d.Get("scope").(string)

	log.Printf("[DEBUG] Reading KMIP scope at %s", scopeListPath)
	configured, err := isScopeConfigured(client, scopeListPath, scope)
	if err != nil {
		// TODO Fix error messaging
		return err
	}
	if !configured {
		log.Printf("[WARN] KMIP scopes not found, removing from state")
		d.SetId("")
		return fmt.Errorf("%w: scope=%q, path=%q", errKMIPScopeNotFound, scope, scopeListPath)
	}

	return nil
}

func kmipSecretScopeUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	scope := d.Get("scope").(string)

	if d.HasChange("path") {
		scopeListPath := d.Get("path").(string) + "/scope"
		log.Printf("[DEBUG] Confirming KMIP scope exists at %s", scopeListPath)
		configured, err := isScopeConfigured(client, scopeListPath, scope)
		if err != nil {
			// TODO Fix error messaging
			return err
		}
		if !configured {
			log.Printf("[WARN] KMIP scope not found")
			return fmt.Errorf("%w: scope=%q, path=%q", errKMIPScopeNotFound, scope, scopeListPath)
		}

		d.SetId(fmt.Sprintf("%s/%s", scopeListPath, scope))
	}

	return kmipSecretScopeRead(d, meta)
}

func kmipSecretScopeDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	scopePath := d.Id()

	log.Printf("[DEBUG] Deleting KMIP scope %q", scopePath)
	_, err := client.Logical().Delete(scopePath)
	if err != nil {
		return fmt.Errorf("error deleting scope %q", scopePath)
	}
	log.Printf("[DEBUG] Deleted KMIP scope %q", scopePath)

	return nil
}

func isScopeConfigured(client *api.Client, path, name string) (bool, error) {
	resp, err := client.Logical().List(path)
	if err != nil {
		return false, fmt.Errorf("error reading KMIP scopes at %s: err=%w", path, err)
	}

	if resp != nil {
		if v, ok := resp.Data["keys"].([]interface{}); ok && v != nil {
			for _, s := range v {
				if s.(string) == name {
					return true, nil
				}
			}
		}
	}

	log.Printf("[WARN] KMIP scopes not found, removing from state")

	return false, nil
}

func getKMIPScopePath(d *schema.ResourceData) string {
	path := d.Get("path").(string)
	scope := d.Get("scope").(string)

	return path + "/scope/" + scope
}
