package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

const tokenParamDeprecationMsg = "This parameter should be moved to the Github Auth backend config " +
	"block. It does nothing in a user/team block."

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

			// These token fields were added and released in error. They do nothing and should be
			// removed at the next major version bump.
			"token_bound_cidrs": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Specifies the blocks of IP addresses which are allowed to use the generated token",
				Optional:    true,
				Deprecated:  tokenParamDeprecationMsg,
			},

			"token_explicit_max_ttl": {
				Type:        schema.TypeInt,
				Description: "Generated Token's Explicit Maximum TTL in seconds",
				Optional:    true,
				Deprecated:  tokenParamDeprecationMsg,
			},

			"token_max_ttl": {
				Type:        schema.TypeInt,
				Description: "The maximum lifetime of the generated token",
				Optional:    true,
				Deprecated:  tokenParamDeprecationMsg,
			},

			"token_no_default_policy": {
				Type:        schema.TypeBool,
				Description: "If true, the 'default' policy will not automatically be added to generated tokens",
				Optional:    true,
				Deprecated:  tokenParamDeprecationMsg,
			},

			"token_period": {
				Type:        schema.TypeInt,
				Description: "Generated Token's Period",
				Optional:    true,
				Deprecated:  tokenParamDeprecationMsg,
			},

			"token_policies": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description:   "Generated Token's Policies",
				ConflictsWith: []string{"policies"},
				Deprecated:    tokenParamDeprecationMsg,
			},

			"token_type": {
				Type:        schema.TypeString,
				Description: "The type of token to generate, service or batch",
				Optional:    true,
				Deprecated:  tokenParamDeprecationMsg,
			},

			"token_ttl": {
				Type:        schema.TypeInt,
				Description: "The initial ttl of the token to generate in seconds",
				Optional:    true,
				Deprecated:  tokenParamDeprecationMsg,
			},

			"token_num_uses": {
				Type:        schema.TypeInt,
				Description: "The maximum number of times a token may be used, a value of zero means unlimited",
				Optional:    true,
				Deprecated:  tokenParamDeprecationMsg,
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
