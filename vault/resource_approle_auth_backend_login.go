package vault

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func approleAuthBackendLoginResource() *schema.Resource {
	return &schema.Resource{
		Create: approleAuthBackendLoginCreate,
		Read:   approleAuthBackendLoginRead,
		Delete: approleAuthBackendLoginDelete,
		Exists: approleAuthBackendLoginExists,

		Schema: map[string]*schema.Schema{
			"role_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The RoleID to log in with.",
				ForceNew:    true,
			},
			"secret_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The SecretID to log in with.",
				ForceNew:    true,
			},
			"policies": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies set on the token.",
			},
			"renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the token is renewable or not.",
			},
			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "How long the token is valid for.",
			},
			"lease_started": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The timestamp the lease started on, as determined by the machine running Terraform.",
			},
			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor for the token.",
			},
			"client_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The token.",
			},
			"metadata": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Metadata associated with the token.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "approle",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func approleAuthBackendLoginCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)

	path := approleAuthBackendLoginPath(backend)

	log.Printf("[DEBUG] Logging in with AppRole auth backend %q", path)
	data := map[string]interface{}{
		"role_id": d.Get("role_id").(string),
	}
	if v, ok := d.GetOk("secret_id"); ok {
		data["secret_id"] = v.(string)
	}

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error logging into AppRole auth backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Logged in with AppRole auth backend %q", path)

	d.SetId(resp.Auth.Accessor)
	d.Set("lease_started", time.Now().Format(time.RFC3339))
	d.Set("client_token", resp.Auth.ClientToken)

	return approleAuthBackendLoginRead(d, meta)
}

func approleAuthBackendLoginRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	log.Printf("[DEBUG] Reading token %q", d.Id())
	resp, err := client.Auth().Token().LookupAccessor(d.Id())
	if err != nil {
		// If the token is not found (it has expired) we don't return an error
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading token %q from Vault: %s", d.Id(), err)
	}
	if resp == nil {
		log.Printf("[DEBUG] Token %q not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Read token %q", d.Id())
	if leaseExpiringSoon(d, client) {
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

	d.Set("policies", resp.Data["policies"])
	d.Set("renewable", resp.Data["renewable"])
	d.Set("lease_duration", resp.Data["lease_duration"])
	d.Set("metadata", resp.Data["metadata"])
	d.Set("accessor", resp.Data["accessor"])
	return nil
}

func approleAuthBackendLoginDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	accessor := d.Id()

	log.Printf("[DEBUG] Revoking token %q", accessor)
	err := client.Auth().Token().RevokeAccessor(accessor)
	if err != nil {
		return fmt.Errorf("error revoking token %q", accessor)
	}
	log.Printf("[DEBUG] Revoked token %q", accessor)

	return nil
}

func approleAuthBackendLoginExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	accessor := d.Id()

	log.Printf("[DEBUG] Checking if token %q exists", accessor)
	resp, err := client.Auth().Token().LookupAccessor(accessor)
	if err != nil {
		// If the token is not found (it has expired) we don't return an error
		if util.IsExpiredTokenErr(err) {
			return false, nil
		}
		return true, fmt.Errorf("error reading %q: %s", accessor, err)
	}
	return resp != nil, nil
}

func approleAuthBackendLoginPath(backend string) string {
	return "auth/" + strings.Trim(backend, "/") + "/login"
}

func leaseExpiringSoon(d *schema.ResourceData, client *api.Client) bool {
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
	// whether the time the lease started plus the number of seconds specified in the duration
	// plus five minutes of buffer is before the current time or not. If it is, we don't need to
	// renew just yet.
	if started.Add(time.Second * time.Duration(duration)).Add(time.Minute * 5).Before(time.Now()) {
		return false
	}
	// if the lease duration expired more than five minutes ago, we can't renew anyways, so don't
	// bother even trying.
	if started.Add(time.Second * time.Duration(duration)).After(time.Now().Add(time.Minute * -5)) {
		return false
	}

	// the lease will expire in the next five minutes, or expired less than five minutes ago, in
	// which case renewing is worth a shot
	return true
}
