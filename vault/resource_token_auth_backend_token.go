package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

var displayNameSanitize = regexp.MustCompile("[^a-zA-Z0-9-]")

func tokenAuthBackendTokenResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenAuthBackendTokenCreate,
		Delete: tokenAuthBackendTokenDelete,
		Read:   tokenAuthBackendTokenRead,

		Schema: map[string]*schema.Schema{
			"display_name": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Display name to associate with token",
				StateFunc: func(in interface{}) string {
					configName := in.(string)
					// the Vault server prefixes all display names with token-, so let's
					// add that, so we'll match
					configName = "token-" + configName

					// the Vault server replaces all non-alphanumeric characters with hyphens
					// so let's apply that to our config value
					configName = displayNameSanitize.ReplaceAllString(configName, "-")

					// the Vault server trims off any trailing hyphens, so we should too
					configName = strings.TrimSuffix(configName, "-")
					return configName
				},
			},

			"policies": {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				ForceNew:    true,
				Description: "Policy to apply to token",
				// This defaults to the default policy if not set
			},

			"meta": {
				Type:        schema.TypeMap,
				Optional:    true,
				ForceNew:    true,
				Description: "A map of string to string valued metadata. This is passed to the audit backends",
			},

			"role": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Role to apply to token",
			},

			"ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "TTL of Vault token in seconds",
			},

			"explicit_max_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "Maximum TTL of Vault token in seconds",
			},

			"renewable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "Make token renewable",
			},

			"period_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "The number of seconds to use as a TTL for each renewal.",
			},

			"wrap": {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Description: "Wrap Vault token",
			},

			"wrap_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "TTL for wrapped token in seconds",
			},

			"num_uses": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "The maximum number of uses for the token. 0 is for unlimited uses.",
			},

			"token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Returned Vault token",
				Sensitive:   true,
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Returned Vault token accessor",
			},
		},
	}
}

func tokenAuthBackendTokenCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(*api.Client)

	wrap := d.Get("wrap")
	if wrap.(bool) {
		// this is a hack to get around the Vault client not having
		// an easy way to set this; the easiest way on a per-request
		// basis instead of on a client-basis is to set the environment
		// variable. However, this ultimately just ends up as an HTTP
		// header, so ideally this is just an option we pass in with
		// the request, because this is a bit weird.
		// See vault issue https://github.com/hashicorp/vault/issues/4294
		// for more information.
		prevWrapTTLEnv := os.Getenv("VAULT_WRAP_TTL")
		os.Setenv("VAULT_WRAP_TTL", strconv.Itoa(d.Get("wrap_ttl_seconds").(int)))
		defer os.Setenv("VAULT_WRAP_TTL", prevWrapTTLEnv)
	}

	options := &api.TokenCreateRequest{
		DisplayName:     d.Get("display_name").(string),
		NoDefaultPolicy: true,
	}
	if v, ok := d.GetOkExists("ttl_seconds"); ok {
		options.TTL = strconv.Itoa(v.(int)) + "s"
	}
	if v, ok := d.GetOkExists("explicit_max_ttl_seconds"); ok {
		options.ExplicitMaxTTL = strconv.Itoa(v.(int)) + "s"
	}

	if v, ok := d.GetOkExists("renewable"); ok {
		r := v.(bool)
		options.Renewable = &r
	}

	if p, ok := d.GetOk("period_seconds"); ok {
		options.Period = strconv.Itoa(p.(int)) + "s"
	}

	if p, ok := d.GetOk("policies"); ok {
		l := p.(*schema.Set).List()
		pol := make([]string, len(l))
		for i, v := range l {
			pol[i] = v.(string)
		}
		options.Policies = pol
	} else {
		options.Policies = []string{"default"}
	}

	if m, ok := d.GetOk("meta"); ok {
		metadata := make(map[string]string)
		for k, v := range m.(map[string]interface{}) {
			metadata[k] = v.(string)
		}

		options.Metadata = metadata
	}

	if uses, ok := d.GetOkExists("num_uses"); ok {
		options.NumUses = uses.(int)
	}

	var token *api.Secret
	var err error
	if role, ok := d.GetOkExists("role"); ok {
		token, err = client.Auth().Token().CreateWithRole(options, role.(string))
	} else {
		token, err = client.Auth().Token().Create(options)
	}
	if err != nil {
		return fmt.Errorf("error creating token: %v", err)
	}

	if token.WrapInfo != nil {
		d.Set("token", token.WrapInfo.Token)
		d.Set("accessor", token.WrapInfo.WrappedAccessor)
		d.SetId(token.WrapInfo.WrappedAccessor)
	} else if token.Auth != nil {
		d.Set("token", token.Auth.ClientToken)
		d.Set("accessor", token.Auth.Accessor)
		d.SetId(token.Auth.Accessor)
	} else {
		return fmt.Errorf("neither wrapped nor auth information returned")
	}

	return tokenAuthBackendTokenRead(d, m)
}

func tokenAuthBackendTokenRead(d *schema.ResourceData, m interface{}) error {
	client := m.(*api.Client)

	secret, err := client.Auth().Token().LookupAccessor(d.Id())
	if err != nil {
		// If we get a bad token error, it has likely been revoked
		// we will therefore remove token from state file
		if strings.HasSuffix(err.Error(), "bad token") {
			log.Printf("[WARN] Received error %q retrieving token %q; assuming it's been revoked, and removing it from state.",
				err.Error(), d.Id())
			d.SetId("")
		}
		return fmt.Errorf("error reading accessor %q: %v", d.Id(), err)
	}

	if d.Get("wrap").(bool) {
		log.Printf("[DEBUG] Ignoring server response for token %q because it has been wrapped, so none of its data will be returned.", d.Id())
		return nil
	}

	if v, ok := secret.Data["display_name"]; ok {
		d.Set("display_name", v.(string))
	} else {
		d.Set("display_name", nil)
	}

	if v, ok := secret.Data["policies"]; ok && v != nil {
		err = d.Set("policies", v.([]interface{}))
		if err != nil {
			return err
		}
	} else {
		d.Set("policies", nil)
	}

	if v, ok := secret.Data["meta"]; ok && v != nil {
		mss := make(map[string]string, len(v.(map[string]interface{})))
		for k, v := range v.(map[string]interface{}) {
			mss[k] = v.(string)
		}
		err = d.Set("meta", mss)
		if err != nil {
			return err
		}
	} else {
		d.Set("meta", nil)
	}

	if v, ok := secret.Data["role"]; ok {
		d.Set("role", v.(string))
	} else {
		d.Set("role", nil)
	}

	if v, ok := secret.Data["creation_ttl"]; ok {
		ttl, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %v for ttl: %s", v, err.Error())
		}
		d.Set("ttl_seconds", ttl)
	} else {
		d.Set("ttl_seconds", nil)
	}

	if v, ok := secret.Data["explicit_max_ttl"]; ok {
		max_ttl, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %v for explicit_max_ttl: %s", v, err.Error())
		}
		d.Set("explicit_max_ttl_seconds", max_ttl)
	} else {
		d.Set("explicit_max_ttl_seconds", nil)
	}

	if v, ok := secret.Data["renewable"]; ok {
		d.Set("renewable", v.(bool))
	} else {
		d.Set("renewable", nil)
	}

	if v, ok := secret.Data["period"]; ok {
		period, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %v for period: %s", v, err.Error())
		}
		d.Set("period_seconds", period)
	} else {
		d.Set("period", nil)
	}

	if v, ok := secret.Data["num_uses"]; ok {
		uses, err := v.(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("unexpected value %v for num_uses: %s", v, err.Error())
		}
		d.Set("num_uses", uses)
	} else {
		d.Set("num_uses", nil)
	}

	return nil
}

func tokenAuthBackendTokenDelete(d *schema.ResourceData, m interface{}) error {
	client := m.(*api.Client)

	if err := client.Auth().Token().RevokeAccessor(d.Id()); err != nil {
		// If we get a bad token error, it has likely been revoked
		// we will therefore remove token from state file
		if strings.HasSuffix(err.Error(), "bad token") {
			return nil
		}
		return fmt.Errorf("Error revoking token: %v", err)
	}

	return nil
}
