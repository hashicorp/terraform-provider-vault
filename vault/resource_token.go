package vault

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func tokenResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenCreate,
		Read:   tokenRead,
		Update: tokenUpdate,
		Delete: tokenDelete,
		Exists: tokenExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The token role name.",
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
				Description: "Flag to create a token without parent.",
			},
			"no_default_policy": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "Flag to disable the default policy.",
			},
			"renewable": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "Flag to allow the token to be renewed",
			},
			"ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The TTL period of the token.",
			},
			"explicit_max_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
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
				Description: "The number of allowed uses of the token.",
			},
			"period": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The period of the token.",
			},
			"renew_min_lease": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The minimum lease to renew token.",
			},
			"renew_increment": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The renew increment.",
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
			"client_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client token.",
				Sensitive:   true,
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

	var createRequest = &api.TokenCreateRequest{}

	if len(policies) > 0 {
		createRequest.Policies = policies
	}

	if v, ok := d.GetOk("ttl"); ok {
		createRequest.TTL = v.(string)
	}

	if v, ok := d.GetOk("explicit_max_ttl"); ok {
		createRequest.ExplicitMaxTTL = v.(string)
	}

	if v, ok := d.GetOk("period"); ok {
		createRequest.Period = v.(string)
	}

	if v, ok := d.GetOk("no_parent"); ok {
		createRequest.NoParent = v.(bool)
	}

	if v, ok := d.GetOk("no_default_policy"); ok {
		createRequest.NoDefaultPolicy = v.(bool)
	}

	if v, ok := d.GetOk("display_name"); ok {
		createRequest.DisplayName = v.(string)
	}

	if v, ok := d.GetOk("num_uses"); ok {
		createRequest.NumUses = v.(int)
	}

	if v, ok := d.GetOk("renewable"); ok {
		renewable := v.(bool)
		createRequest.Renewable = &renewable
	}

	var resp *api.Secret
	var err error

	if role != "" {
		log.Printf("[DEBUG] Creating token with role %q", role)
		resp, err = client.Auth().Token().CreateWithRole(createRequest, role)
		if err != nil {
			return fmt.Errorf("error creating token with role %q: %s", role, err)
		}

		log.Printf("[DEBUG] Created token accessor %q with role %q", resp.Auth.Accessor, role)
	} else {
		log.Printf("[DEBUG] Creating token")
		resp, err = client.Auth().Token().Create(createRequest)
		if err != nil {
			return fmt.Errorf("error creating token: %s", err)
		}

		log.Printf("[DEBUG] Created token accessor %q", resp.Auth.Accessor)
	}

	d.Set("lease_duration", resp.Auth.LeaseDuration)
	d.Set("lease_started", time.Now().Format(time.RFC3339))
	d.Set("client_token", resp.Auth.ClientToken)

	d.SetId(resp.Auth.Accessor)

	return tokenRead(d, meta)
}

func tokenRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	id := d.Id()

	log.Printf("[DEBUG] Reading token accessor %q", id)
	resp, err := client.Auth().Token().LookupAccessor(id)
	if err != nil {
		log.Printf("[WARN] Token not found, removing from state")
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Read token accessor %q", id)

	iPolicies := resp.Data["policies"].([]interface{})
	policies := make([]string, 0, len(iPolicies))
	for _, iPolicy := range iPolicies {
		if iPolicy == "default" {
			continue
		}

		policies = append(policies, iPolicy.(string))
	}

	d.Set("policies", policies)
	d.Set("no_parent", fmt.Sprintf("%v", resp.Data["orphan"]))
	d.Set("renewable", fmt.Sprintf("%v", resp.Data["renewable"]))
	d.Set("display_name", strings.TrimPrefix(resp.Data["display_name"].(string), "token-"))
	d.Set("num_uses", resp.Data["num_uses"])

	if d.Get("renewable").(bool) && tokenCheckLease(d) {
		log.Printf("[DEBUG] Lease for token accessor %q expiring soon, renewing", d.Id())

		increment := d.Get("lease_duration").(int)

		if v, ok := d.GetOk("renew_increment"); ok {
			increment = v.(int)
		}

		renewed, err := client.Auth().Token().RenewSelf(increment)
		if err != nil {
			log.Printf("[DEBUG] Error renewing token, removing from state")
			d.SetId("")
			return nil
		}

		log.Printf("[DEBUG] Lease for token accessor %q renewed, new lease duration %d", d.Id(),
			renewed.Auth.LeaseDuration)

		d.Set("lease_duration", renewed.Data["lease_duration"])
		d.Set("lease_started", time.Now().Format(time.RFC3339))
		d.Set("client_token", renewed.Auth.ClientToken)

		d.SetId(renewed.Auth.Accessor)
	}

	return nil
}

func tokenUpdate(d *schema.ResourceData, meta interface{}) error {
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
	log.Printf("[DEBUG] Deleted token accessor %q", token)

	return nil
}

func tokenExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	accessor := d.Id()

	log.Printf("[DEBUG] Checking if token accessor %q exists", accessor)
	resp, err := client.Auth().Token().LookupAccessor(accessor)
	if err != nil {
		log.Printf("[DEBUG] token accessor %q not found: %s", d.Id(), err)
		return false, nil
	}
	return resp != nil, nil
}

func tokenCheckLease(d *schema.ResourceData) bool {
	startedStr := d.Get("lease_started").(string)
	if startedStr == "" {
		return false
	}

	started, err := time.Parse(time.RFC3339, startedStr)
	if err != nil {
		log.Printf("[DEBUG] lease_started %q for token accessor %q is an invalid value, removing: %s", startedStr,
			d.Id(), err)
		d.SetId("")

		return false
	}

	leaseDuration := d.Get("lease_duration").(int)

	expireTime := started.Add(time.Second * time.Duration(leaseDuration))
	if expireTime.Before(time.Now()) {
		log.Printf("[DEBUG] token accessor %q has expired", d.Id())
		d.SetId("")

		return false
	}

	if v, ok := d.GetOk("renew_min_lease"); ok {
		renewMinLease := v.(int)
		if renewMinLease <= 0 {
			return false
		}

		renewTime := int(expireTime.Sub(time.Now()).Seconds())
		if renewTime <= renewMinLease {
			log.Printf("[DEBUG] token accessor %q must be renewed", d.Id())

			return true
		}
	}

	return false
}
