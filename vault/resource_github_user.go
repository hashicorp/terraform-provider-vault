package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func githubUserTokenConfig() *addTokenFieldsConfig {
	return &addTokenFieldsConfig{
		TokenPoliciesConflict: []string{"policies"},
	}
}

func githubUserResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Auth backend to which user mapping will be congigured.",
			ForceNew:    true,
			Default:     "github",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"user": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "GitHub user name.",
		},
		"policies": {
			Type:          schema.TypeList,
			Optional:      true,
			Elem:          &schema.Schema{Type: schema.TypeString},
			Description:   "Policies to be assigned to this team.",
			Deprecated:    "use `token_policies` instead",
			ConflictsWith: []string{"token_policies"},
		},
	}

	addTokenFields(fields, githubUserTokenConfig())

	return &schema.Resource{
		Create: githubUserCreate,
		Read:   githubUserRead,
		Update: githubUserUpdate,
		Delete: githubUserDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func githubUserUpdateFields(d *schema.ResourceData, data map[string]interface{}) error {
	setTokenFields(d, data, githubUserTokenConfig())

	data["key"] = d.Get("user").(string)
	if v, ok := d.GetOk("policies"); ok {
		vs := expandStringSlice(v.([]interface{}))
		data["value"] = strings.Join(vs, ",")
	}

	return nil
}

func githubUserCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	id := githubMapId(d.Get("backend").(string), d.Get("user").(string), "users")
	d.SetId(id)
	d.MarkNewResource()

	data := map[string]interface{}{}
	githubUserUpdateFields(d, data)

	log.Printf("[INFO] Creating new github user map at '%v'", id)
	_, err := client.Logical().Write(id, data)
	if err != nil {
		d.SetId("")
		return err
	}

	log.Printf("[INFO] Saved github user map at '%v'", id)

	return githubUserRead(d, meta)
}

func githubUserUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}
	githubUserUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return err
	}

	log.Printf("[INFO] Saved github user map at '%v'", path)

	return githubUserRead(d, meta)
}

func githubUserRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	dt, err := client.Logical().Read(path)
	if err != nil {
		log.Printf("[ERROR] error when reading github user mapping from '%s'", path)
		return err
	}

	readTokenFields(d, dt)

	// Check if the user is using the deprecated `policies`
	if _, deprecated := d.GetOk("policies"); deprecated {
		// Then we see if `token_policies` was set and unset it
		// Vault will still return `policies`
		if _, ok := d.GetOk("token_policies"); ok {
			d.Set("token_policies", nil)
		}
	}

	if v, ok := dt.Data["key"]; ok {
		d.Set("user", v.(string))
	} else {
		return fmt.Errorf("github user information not found at path: '%v'", d.Id())
	}

	if v, ok := dt.Data["value"]; ok {
		policies := flattenCommaSeparatedStringSlice(v.(string))
		if err := d.Set("policies", policies); err != nil {
			return err
		}
	}

	d.Set("backend", githubMappingPath(d.Id(), "users"))

	return nil
}

func githubUserDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	_, err := client.Logical().Delete(d.Id())
	if err != nil {
		return err
	}
	return nil
}
