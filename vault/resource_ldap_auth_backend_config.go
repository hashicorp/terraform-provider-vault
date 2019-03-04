package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	ldapAuthBackendConfigFromPathRegex = regexp.MustCompile("^auth/(.+)/config$")
)

func ldapAuthBackendConfigResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: ldapAuthBackendConfigCreate,
		Update: ldapAuthBackendConfigUpdate,
		Read:   ldapAuthBackendConfigRead,
		Delete: ldapAuthBackendConfigDelete,
		Exists: ldapAuthBackendConfigExists,

		Schema: map[string]*schema.Schema{
			"url": {
				Type:     schema.TypeString,
				Required: true,
			},
			"starttls": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"tls_min_version": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"tls_max_version": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"insecure_tls": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"certificate": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"binddn": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"bindpass": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"userdn": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"userattr": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				StateFunc: func(v interface{}) string {
					return strings.ToLower(v.(string))
				},
			},
			"discoverdn": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"deny_null_bind": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"upndomain": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"groupfilter": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"groupdn": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"groupattr": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the ldap backend to configure.",
				ForceNew:    true,
				Default:     "ldap",
				// standardise on no beginning or trailing slashes
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

func ldapAuthBackendConfigBackendFromPath(path string) (string, error) {
	if !ldapAuthBackendConfigFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := ldapAuthBackendConfigFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func ldapAuthBackendConfigCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)
	path := ldapAuthBackendConfigPath(backend)
	log.Printf("[DEBUG] Writing ldap auth backend config %q", path)

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

	d.SetId(path)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing ldap config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote LDAP config %q", path)

	return ldapAuthBackendConfigRead(d, meta)
}

func ldapAuthBackendConfigUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating ldap auth backend config %q", path)

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
		return fmt.Errorf("error updating ldap config %q: %s", path, err)
	}

	// NOTE: Only `SetId` after it's successfully written in Vault
	d.SetId(path)

	log.Printf("[DEBUG] Wrote LDAP config %q", path)

	return ldapAuthBackendConfigRead(d, meta)
}

func ldapAuthBackendConfigRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := ldapAuthBackendConfigBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for ldap auth backend config: %s", path, err)
	}

	log.Printf("[DEBUG] Reading ldap auth backend config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading ldap auth backend config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read ldap auth backend config %q", path)
	if resp == nil {
		log.Printf("[WARN] ldap auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("backend", backend)
	d.Set("url", resp.Data["url"])
	d.Set("starttls", resp.Data["starttls"])
	d.Set("tls_min_version", resp.Data["tls_min_version"])
	d.Set("tls_max_version", resp.Data["tls_max_version"])
	d.Set("insecure_tls", resp.Data["insecure_tls"])
	d.Set("certificate", resp.Data["certificate"])
	d.Set("binddn", resp.Data["binddn"])
	d.Set("userdn", resp.Data["userdn"])
	d.Set("userattr", resp.Data["userattr"])
	d.Set("discoverdn", resp.Data["discoverdn"])
	d.Set("deny_null_bind", resp.Data["deny_null_bind"])
	d.Set("upndomain", resp.Data["upndomain"])
	d.Set("groupfilter", resp.Data["groupfilter"])
	d.Set("groupdn", resp.Data["groupdn"])
	d.Set("groupattr", resp.Data["groupattr"])

	// `bindpass` cannot be read out from the API
	// So... if they drift, they drift.

	return nil
}

func ldapAuthBackendConfigDelete(d *schema.ResourceData, meta interface{}) error {
	path := d.Id()
	log.Printf("[DEBUG] Deleted ldap auth backend config %q", path)
	d.SetId("")
	return nil
}

func ldapAuthBackendConfigExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if ldap auth backend config %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if ldap auth backend config %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if ldap auth backend config %q exists", path)

	return resp != nil, nil
}
