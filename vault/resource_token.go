package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"strings"
)

func tokenResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenCreate,
		Read:   tokenRead,
		Delete: tokenDelete,

		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     "",
				Description: "The client token.",
			},
			"policies": {
				Type:     schema.TypeSet,
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
				Default:     false,
				Description: "Flag to create a token without parent.",
			},
			"no_default_policy": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     false,
				Description: "Flag to disable the default policy.",
			},
			"renewable": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     true,
				Description: "Flag to allow the token to be renewed",
			},
			"ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     "",
				Description: "The TTL period of the token.",
			},
			"explicit_max_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     "",
				Description: "The explicit max TTL of the token.",
			},
			"display_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     "token",
				Description: "The display name of the token.",
			},
			"num_uses": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     0,
				Description: "The number of allowed uses of the token.",
			},
			"period": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     "",
				Description: "The period of the token.",
			},
			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The token lease duration.",
			},
			"lease_started": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The token lease started on.",
			},
			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client token accessor.",
			},
			"client_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client token.",
			},
		},
	}
}

func tokenCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	role := d.Get("role_name").(string)

	iPolicies := d.Get("policies").(*schema.Set).List()
	policies := make([]string, 0, len(iPolicies))
	for _, iPolicy := range iPolicies {
		policies = append(policies, iPolicy.(string))
	}

	var createRequest = &api.TokenCreateRequest{
		NoParent:        d.Get("no_parent").(bool),
		NoDefaultPolicy: d.Get("no_default_policy").(bool),
		TTL:             d.Get("ttl").(string),
		ExplicitMaxTTL:  d.Get("explicit_max_ttl").(string),
		DisplayName:     d.Get("display_name").(string),
		NumUses:         d.Get("num_uses").(int),
		Period:          d.Get("period").(string),
	}

	renewable := d.Get("renewable").(bool)
	createRequest.Renewable = &renewable

	if len(policies) > 0 {
		createRequest.Policies = policies
	}

	var resp *api.Secret
	var err error

	if role != "" {
		log.Printf("[DEBUG] Creating token with role %q", role)
		resp, err = client.Auth().Token().CreateWithRole(createRequest, role)
		if err != nil {
			return fmt.Errorf("error creating token with role %q: %s", role, err)
		}

		log.Printf("[DEBUG] Created token %q with role %q", resp.Auth.Accessor, role)
	} else {
		log.Printf("[DEBUG] Creating token")
		resp, err = client.Auth().Token().Create(createRequest)
		if err != nil {
			return fmt.Errorf("error creating token: %s", err)
		}

		log.Printf("[DEBUG] Created token %q", resp.Auth.Accessor)
	}

	d.Set("lease_started", time.Now().Format(time.RFC3339))
	d.Set("accessor", resp.Auth.Accessor)
	d.Set("client_token", resp.Auth.ClientToken)

	d.SetId(resp.Auth.Accessor)

	return tokenRead(d, meta)
}

func tokenRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	id := d.Id()

	log.Printf("[DEBUG] Reading token %q", id)
	resp, err := client.Auth().Token().LookupAccessor(id)
	if err != nil {
		log.Printf("[WARN] Token not found, removing from state")
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Read token %q", id)

	if tokenCheckLease(d, client) {
		log.Printf("[DEBUG] Lease for %q expiring soon, renewing", d.Id())
		renewed, err := client.Auth().Token().Renew(d.Get("client_token").(string), d.Get("lease_duration").(int))
		if err != nil {
			log.Printf("[DEBUG] Error renewing token %q, bailing", d.Id())
		} else {
			resp = renewed
			d.Set("lease_started", time.Now().Format(time.RFC3339))
			d.Set("client_token", resp.Auth.ClientToken)

			d.SetId(resp.Auth.Accessor)
		}
	}

	iPolicies := resp.Data["policies"].([]interface{})
	policies := make([]string, 0, len(iPolicies))
	for _, iPolicy := range iPolicies {
		if iPolicy == "default" {
			continue
		}

		policies = append(policies, iPolicy.(string))
	}

	d.Set("policies", policies)
	d.Set("no_parent", resp.Data["orphan"])
	d.Set("renewable", resp.Data["renewable"])
	d.Set("display_name", strings.TrimPrefix(resp.Data["display_name"].(string), "token-"))
	d.Set("num_uses", resp.Data["num_uses"])
	d.Set("period", resp.Data["period"])
	d.Set("lease_duration", resp.Data["lease_duration"])
	d.Set("accessor", resp.Data["accessor"])

	return nil
}

func tokenDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	token := d.Id()

	log.Printf("[DEBUG] Deleting token %q", token)
	err := client.Auth().Token().RevokeAccessor(token)
	if err != nil {
		return fmt.Errorf("error deleting token %q: %s", token, err)
	}
	log.Printf("[DEBUG] Deleted token %q", token)

	return nil
}

func tokenCheckLease(d *schema.ResourceData, client *api.Client) bool {
	startedStr := d.Get("lease_started").(string)
	duration := d.Get("lease_duration").(int)
	if startedStr == "" {
		return false
	}

	started, err := time.Parse(time.RFC3339, startedStr)
	if err != nil {
		log.Printf("[DEBUG] lease_started %q for %q is an invalid value, removing: %s", startedStr, d.Id(), err)
		d.Set("lease_started", "")

		return false
	}

	if started.Add(time.Second * time.Duration(duration)).Add(time.Minute * 5).Before(time.Now()) {
		return false
	}

	if started.Add(time.Second * time.Duration(duration)).After(time.Now().Add(time.Minute * -5)) {
		return false
	}

	return true
}
