package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func githubTeamTokenConfig() *addTokenFieldsConfig {
	return &addTokenFieldsConfig{
		TokenPoliciesConflict: []string{"policies"},
	}
}

func githubTeamResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Auth backend to which team mapping will be congigured.",
			ForceNew:    true,
			Default:     "github",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"team": {
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			Description:  "GitHub team name in \"slugified\" format.",
			ValidateFunc: validateStringSlug,
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

	addTokenFields(fields, githubTeamTokenConfig())

	return &schema.Resource{
		Create: githubTeamCreate,
		Read:   githubTeamRead,
		Update: githubTeamUpdate,
		Delete: githubTeamDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func githubTeamUpdateFields(d *schema.ResourceData, data map[string]interface{}) error {
	setTokenFields(d, data, githubTeamTokenConfig())

	data["key"] = d.Get("team").(string)
	if v, ok := d.GetOk("policies"); ok {
		vs := expandStringSlice(v.([]interface{}))
		data["value"] = strings.Join(vs, ",")
	}

	return nil
}

func githubTeamCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := githubMapId(d.Get("backend").(string), d.Get("team").(string), "teams")
	d.SetId(id)
	d.MarkNewResource()

	data := map[string]interface{}{}
	githubTeamUpdateFields(d, data)

	log.Printf("[INFO] Creating new github team map at '%v'", id)

	_, err := client.Logical().Write(id, data)
	if err != nil {
		d.SetId("")
		return err
	}

	log.Printf("[INFO] Saved github team map at '%v'", id)

	return githubTeamRead(d, meta)
}

func githubTeamUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}
	githubTeamUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return err
	}

	log.Printf("[INFO] Saved github team map at '%v'", path)

	return githubTeamRead(d, meta)
}

func githubTeamRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	dt, err := client.Logical().Read(path)
	if err != nil {
		log.Printf("[ERROR] error when reading github team mapping from '%s'", path)
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
		d.Set("team", v.(string))
	} else {
		return fmt.Errorf("github team information not found at path: '%v'", d.Id())
	}

	if v, ok := dt.Data["value"]; ok {
		policies := flattenCommaSeparatedStringSlice(v.(string))
		if err := d.Set("policies", policies); err != nil {
			return err
		}
	}

	d.Set("backend", githubMappingPath(d.Id(), "teams"))

	return nil
}

func githubTeamDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	_, err := client.Logical().Delete(d.Id())
	if err != nil {
		return err
	}
	return nil
}
