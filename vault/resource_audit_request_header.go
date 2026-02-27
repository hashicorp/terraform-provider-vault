// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"

	"github.com/hashicorp/vault/api"
)

func auditRequestHeaderPath(name string) string {
	return "sys/config/auditing/request-headers/" + name
}

func auditRequestHeaderResource() *schema.Resource {
	return &schema.Resource{
		Create: auditRequestHeaderCreate,
		Read:   provider.ReadWrapper(auditRequestHeaderRead),
		Update: auditRequestHeaderUpdate,
		Delete: auditRequestHeaderDelete,
		Exists: auditRequestHeaderExists,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the request header to audit.",
			},
			"hmac": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether this header's value should be HMAC'd in the audit logs.",
			},
		},
	}
}

func auditRequestHeaderCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)
	path := auditRequestHeaderPath(name)
	d.SetId(name)

	log.Printf("[DEBUG] Creating Resource Audit Request Header %s", name)

	data := map[string]interface{}{}

	if v, ok := d.GetOk("hmac"); ok {
		data["hmac"] = v
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("error creating Resource Audit Request Header %s: %w", name, err)
	}
	log.Printf("[DEBUG] Created Resource Audit Request Header %s", name)

	return auditRequestHeaderRead(d, meta)
}

func auditRequestHeaderRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := auditRequestHeaderPath(name)

	log.Printf("[DEBUG] Reading Resource Audit Request Header %s", name)
	resp, err := client.Logical().Read(path)
	if err != nil {
		// This endpoint returns a 400 if the header does not exist, rather than
		// a 404/empty response.
		if apiErr, ok := err.(*api.ResponseError); !ok || apiErr.StatusCode != 400 ||
			len(apiErr.Errors) != 1 || apiErr.Errors[0] != "Could not find header in config" {

			return fmt.Errorf("error reading Resource Audit Request Header %s: %w", name, err)
		}
	}

	if resp == nil {
		log.Printf("[WARN] Resource Audit Request Header %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	if hmac, ok := resp.Data[name].(map[string]interface{})["hmac"]; ok {
		if err := d.Set("hmac", hmac); err != nil {
			return fmt.Errorf("error setting hmac for Resource Audit Request Header %s: %w", name, err)
		}
	}

	return nil
}

func auditRequestHeaderUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := auditRequestHeaderPath(name)

	log.Printf("[DEBUG] Updating Resource Audit Request Header %s", name)

	data := map[string]interface{}{}

	if v, ok := d.GetOk("hmac"); ok {
		data["hmac"] = v
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("error updating Resource Audit Request Header %s: %w", name, err)
	}
	log.Printf("[DEBUG] Updated Resource Audit Request Header %s", name)

	return auditRequestHeaderRead(d, meta)
}

func auditRequestHeaderDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := auditRequestHeaderPath(name)

	log.Printf("[DEBUG] Deleting Resource Audit Request Header %s", name)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting Resource Audit Request Header %s: %w", name, err)
	}
	log.Printf("[DEBUG] Deleted Resource Audit Request Header %s", name)

	return nil
}

func auditRequestHeaderExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	name := d.Id()
	path := auditRequestHeaderPath(name)

	log.Printf("[DEBUG] Checking if Resource Audit Request Header %s exists", name)

	secret, err := client.Logical().Read(path)
	if err != nil {
		// This endpoint returns a 400 if the header does not exist, rather than
		// a 404/empty response.
		if apiErr, ok := err.(*api.ResponseError); ok && apiErr.StatusCode == 400 &&
			len(apiErr.Errors) == 1 && apiErr.Errors[0] == "Could not find header in config" {

			return false, nil
		}

		return true, fmt.Errorf("error checking if Resource Audit Request Header %s exists: %w", name, err)
	}

	log.Printf("[DEBUG] Checked if Resource Audit Request Header %s exists", name)
	return secret != nil, nil
}
