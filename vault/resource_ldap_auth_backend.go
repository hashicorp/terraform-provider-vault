package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"

	"github.com/hashicorp/vault/api"
)

const ldapAuthType string = "ldap"

func ldapAuthBackendResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: ldapAuthBackendWrite,
		Update: ldapAuthBackendUpdate,
		Read:   ldapAuthBackendRead,
		Delete: ldapAuthBackendDelete,
		Exists: ldapAuthBackendExists,

		Schema: map[string]*schema.Schema{
			"url": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"starttls": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"tls_min_version": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"tls_max_version": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"insecure_tls": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"certificate": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"binddn": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"bindpass": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"userdn": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"userattr": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				StateFunc: func(v interface{}) string {
					return strings.ToLower(v.(string))
				},
			},
			"discoverdn": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"deny_null_bind": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"upndomain": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"groupfilter": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"groupdn": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"groupattr": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"description": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"path": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "ldap",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func ldapAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}

func ldapAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	authType := ldapAuthType
	path := d.Get("path").(string)
	desc := d.Get("description").(string)

	log.Printf("[DEBUG] Enabling LDAP auth backend %q", path)
	err := client.Sys().EnableAuth(path, authType, desc)
	if err != nil {
		return fmt.Errorf("Error enabling LDAP auth backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled LDAP auth backend %q", path)

	d.SetId(path)

	return ldapAuthBackendUpdate(d, meta)
}

func ldapAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := ldapAuthBackendConfigPath(d.Id())
	data := map[string]interface{}{}

	if v, ok := d.GetOk("url"); ok {
		data["url"] = v.(string)
	}

	if v, ok := d.GetOkExists("starttls"); ok {
		data["starttls"] = v.(bool)
	}

	if v, ok := d.GetOk("tls_min_version"); ok {
		data["tls_min_version"] = v.(string)
	}

	if v, ok := d.GetOk("tls_max_version"); ok {
		data["tls_max_version"] = v.(string)
	}

	if v, ok := d.GetOkExists("insecure_tls"); ok {
		data["insecure_tls"] = v.(bool)
	}

	if v, ok := d.GetOk("certificate"); ok {
		data["certificate"] = v.(string)
	}

	if v, ok := d.GetOk("binddn"); ok {
		data["binddn"] = v.(string)
	}

	if v, ok := d.GetOk("bindpass"); ok {
		data["bindpass"] = v.(string)
	}

	if v, ok := d.GetOk("userdn"); ok {
		data["userdn"] = v.(string)
	}

	if v, ok := d.GetOk("userattr"); ok {
		data["userattr"] = v.(string)
	}

	if v, ok := d.GetOkExists("discoverdn"); ok {
		data["discoverdn"] = v.(bool)
	}

	if v, ok := d.GetOkExists("deny_null_bind"); ok {
		data["deny_null_bind"] = v.(bool)
	}

	if v, ok := d.GetOk("upndomain"); ok {
		data["upndomain"] = v.(string)
	}

	if v, ok := d.GetOk("groupfilter"); ok {
		data["groupfilter"] = v.(string)
	}

	if v, ok := d.GetOk("groupdn"); ok {
		data["groupdn"] = v.(string)
	}

	if v, ok := d.GetOk("groupattr"); ok {
		data["groupattr"] = v.(string)
	}

	log.Printf("[DEBUG] Writing LDAP config %q", path)
	_, err := client.Logical().Write(path, data)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing LDAP config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote LDAP config %q", path)

	return ldapAuthBackendRead(d, meta)
}

func ldapAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := ldapAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Reading LDAP auth backend config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading LDAP auth backend config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read LDAP auth backend config %q", path)

	if resp == nil {
		log.Printf("[WARN] LDAP auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("url", resp.Data["url"])
	d.Set("starttls", resp.Data["starttls"])
	d.Set("tls_min_version", resp.Data["tls_min_version"])
	d.Set("tls_max_version", resp.Data["tls_max_version"])
	d.Set("insecure_tls", resp.Data["insecure_tls"])
	d.Set("certificate", resp.Data["certificate"])
	d.Set("binddn", resp.Data["binddn"])
	d.Set("bindpass", resp.Data["bindpass"])
	d.Set("userdn", resp.Data["userdn"])
	d.Set("userattr", resp.Data["userattr"])
	d.Set("discoverdn", resp.Data["discoverdn"])
	d.Set("deny_null_bind", resp.Data["deny_null_bind"])
	d.Set("upndomain", resp.Data["upndomain"])
	d.Set("groupfilter", resp.Data["groupfilter"])
	d.Set("groupdn", resp.Data["groupdn"])
	d.Set("groupattr", resp.Data["groupattr"])

	return nil
}

func ldapAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting LDAP auth backend %q", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("Error deleting LDAP auth backend %q: %q", path, err)
	}
	log.Printf("[DEBUG] Deleted LDAP auth backend %q", path)

	return nil
}

func ldapAuthBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := ldapAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Checking if LDAP auth backend %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("Error checking for existence of LDAP config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if LDAP auth backend %q exists", path)

	return resp != nil, nil
}
