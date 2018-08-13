package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func tokenResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenCreate,
		Read:   tokenRead,
		Delete: tokenDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The client token.",
			},
			"policies": {
				Type:     schema.TypeList,
				Required: false,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of policies.",
			},
			"no_parent": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "Flag to create a token without parent.",
				Default:     false,
			},
			"no_default_policy": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "Flag to disable the default policy.",
				Default:     false,
			},
			"renewable": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "Flag to allow the token to be renewed",
				Default:     true,
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The TTL period of the token.",
			},
			"explicit_max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The explicit max TTL of the token.",
			},
			"display_name": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The display name of the token.",
				Default:     "token",
			},
			"num_uses": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "The number of allowed uses of the token.",
			},
			"period": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The period of the token.",
			},
			"client_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client token.",
			},
			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client token accessor.",
			},
		},
	}
}

func tokenCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	iPolicies := d.Get("policies").([]interface{})
	policies := make([]string, 0, len(iPolicies))
	for _, iPolicy := range iPolicies {
		policies = append(policies, iPolicy.(string))
	}

	data := map[string]interface{}{
		"role_name":         d.Get("role_name").(string),
		"no_parent":         d.Get("no_parent").(bool),
		"no_default_policy": d.Get("no_default_policy").(bool),
		"renewable":         d.Get("renewable").(bool),
		"ttl":               d.Get("ttl").(string),
		"explicit_max_ttl":  d.Get("explicit_max_ttl").(string),
		"display_name":      d.Get("display_name").(string),
		"num_uses":          d.Get("num_uses").(int),
		"period":            d.Get("period").(string),
	}

	if len(policies) > 0 {
		data["policies"] = policies
	}

	log.Printf("[DEBUG] Creating token")
	resp, err := client.Logical().Write("auth/token/create", data)
	if err != nil {
		return fmt.Errorf("error creating token: %s", err)
	}
	log.Printf("[DEBUG] Created token")

	d.Set("client_token", resp.Auth.ClientToken)
	d.Set("accessor", resp.Auth.Accessor)

	id := d.Get("client_token").(string)

	d.SetId(id)

	return tokenRead(d, meta)
}

func tokenRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	token := d.Id()

	data := map[string]interface{}{
		"token": d.Id(),
	}

	log.Printf("[DEBUG] Reading token %q", token)
	resp, err := client.Logical().Write("auth/token/lookup", data)
	log.Printf("[DEBUG] Read token")
	if (err != nil) || (resp == nil) {
		log.Printf("[WARN] Token not found, removing from state")
		d.SetId("")
		return nil
	}

	return nil
}

func tokenDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	token := d.Id()

	data := map[string]interface{}{
		"token": token,
	}

	log.Printf("[DEBUG] Deleting token %q", token)
	_, err := client.Logical().Write("auth/token/revoke", data)
	if err != nil {
		return fmt.Errorf("error deleting token %q: %s", token, err)
	}
	log.Printf("[DEBUG] Deleted token %q", token)

	return nil
}
