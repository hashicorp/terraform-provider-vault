package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func githubTeamResource() *schema.Resource {
	return &schema.Resource{
		Create: githubTeamCreate,
		Read:   githubTeamRead,
		Update: githubTeamUpdate,
		Delete: githubTeamDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
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
			"policies": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Policies to be assigned to this team.",
			},
			"team": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "GitHub team name in \"slugified\" format.",
				ValidateFunc: validateStringSlug,
			},
		},
	}
}

func githubTeamCreate(d *schema.ResourceData, meta interface{}) error {
	id := githubMapId(d.Get("backend").(string), d.Get("team").(string), "teams")
	d.SetId(id)
	d.MarkNewResource()

	log.Printf("[INFO] Creating new github team map at '%v'", id)
	return githubTeamUpdate(d, meta)
}

func githubTeamUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}
	data["key"] = d.Get("team").(string)
	if v, ok := d.GetOk("policies"); ok {
		vs := expandStringSlice(v.([]interface{}))
		data["value"] = strings.Join(vs, ",")
	}

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
