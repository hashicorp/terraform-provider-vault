package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/hashicorp/vault/api"
)

func certAuthBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: certAuthResourceWrite,
		Update: certAuthResourceUpdate,
		Read:   certAuthResourceRead,
		Delete: certAuthResourceRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"certificate": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"allowed_names": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"allowed_common_names": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"allowed_dns_sans": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"allowed_email_sans": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"allowed_uri_sans": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"allowed_organization_units": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"required_extensions": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"ttl": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"max_ttl": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"period": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"policies": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"display_name": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"backend": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "cert",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"bound_cidrs": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
		},
	}
}

func certCertResourcePath(backend, name string) string {
	return "auth/" + strings.Trim(backend, "/") + "/certs/" + strings.Trim(name, "/")
}

func certAuthResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := certCertResourcePath(backend, name)

	data := map[string]interface{}{}
	data["certificate"] = d.Get("certificate")

	if v, ok := d.GetOk("allowed_names"); ok {
		data["allowed_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_common_names"); ok {
		data["allowed_common_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_dns_sans"); ok {
		data["allowed_dns_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_uri_sans"); ok {
		data["allowed_uri_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_organization_units"); ok {
		data["allowed_organization_units"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("required_extensions"); ok {
		data["required_extensions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(string)
	}

	if v, ok := d.GetOk("policies"); ok {
		data["policies"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("display_name"); ok {
		data["display_name"] = v.(string)
	}

	if v, ok := d.GetOk("bound_cidrs"); ok {
		data["bound_cidrs"] = v.(*schema.Set).List()
	}

	log.Printf("[DEBUG] Writing %q to cert auth backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing %q to cert auth backendq: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote %q to cert auth backend", path)

	return certAuthResourceRead(d, meta)
}

func certAuthResourceUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}

	data["certificate"] = d.Get("certificate")

	if v, ok := d.GetOk("allowed_names"); ok {
		data["allowed_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_common_names"); ok {
		data["allowed_common_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_dns_sans"); ok {
		data["allowed_dns_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_uri_sans"); ok {
		data["allowed_uri_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_organization_units"); ok {
		data["allowed_organization_units"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("required_extensions"); ok {
		data["required_extensions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(string)
	}

	if v, ok := d.GetOk("policies"); ok {
		data["policies"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("display_name"); ok {
		data["display_name"] = v.(string)
	}

	if v, ok := d.GetOk("bound_cidrs"); ok {
		data["bound_cidrs"] = v.(*schema.Set).List()
	}

	log.Printf("[DEBUG] Updating %q in cert auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating %q in cert auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Updated %q in cert auth backend", path)

	return certAuthResourceRead(d, meta)
}

func certAuthResourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading cert %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading cert %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read cert %q", path)

	if resp == nil {
		log.Printf("[WARN] cert %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("certificate", resp.Data["certificate"])
	d.Set("display_name", resp.Data["display_name"])
	d.Set("ttl", resp.Data["ttl"])
	d.Set("max_ttl", resp.Data["max_ttl"])
	d.Set("period", resp.Data["period"])

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_names"] != nil {
		d.Set("allowed_names",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_names"].([]interface{})))
	} else {
		d.Set("allowed_names",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_dns_sans"] != nil {
		d.Set("allowed_dns_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_dns_sans"].([]interface{})))
	} else {
		d.Set("allowed_dns_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_email_sans"] != nil {
		d.Set("allowed_email_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_email_sans"].([]interface{})))
	} else {
		d.Set("allowed_email_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_uri_sans"] != nil {
		d.Set("allowed_uri_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_uri_sans"].([]interface{})))
	} else {
		d.Set("allowed_uri_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_organization_units"] != nil {
		d.Set("allowed_organization_units",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_organization_units"].([]interface{})))
	} else {
		d.Set("allowed_organization_units",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["policies"] != nil {
		d.Set("policies",
			schema.NewSet(
				schema.HashString, resp.Data["policies"].([]interface{})))
	} else {
		d.Set("policies",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["required_extensions"] != nil {
		d.Set("required_extensions",
			schema.NewSet(
				schema.HashString, resp.Data["required_extensions"].([]interface{})))
	} else {
		d.Set("required_extensions",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["bound_cidrs"] != nil {
		d.Set("bound_cidrs",
			schema.NewSet(
				schema.HashString, resp.Data["bound_cidrs"].([]interface{})))
	} else {
		d.Set("bound_cidrs",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	return nil
}

func certAuthResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting cert %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting cert %q", path)
	}
	log.Printf("[DEBUG] Deleted cert %q", path)

	return nil
}
