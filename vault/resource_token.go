package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func tokenResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenCreate,
		Update: tokenCreate,
		Delete: tokenDelete,
		Read:   tokenRead,

		Schema: map[string]*schema.Schema{
			"display_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Display name to associate with token",
			},

			"policies": &schema.Schema{
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				ForceNew:    true,
				Description: "Policy to apply to token",
				// This defaults to the default policy if not set
			},

			"meta": &schema.Schema{
				Type:        schema.TypeMap,
				Optional:    true,
				ForceNew:    true,
				Description: "A map of string to string valued metadata. This is passed to the audit backends",
			},

			"role": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Role to apply to token",
			},

			"ttl": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "768h",
				ForceNew:    true,
				Description: "TTL of Vault token",
			},

			"explicit_max_ttl": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "768h",
				ForceNew:    true,
				Description: "Maximum TTL of Vault token",
			},

			"orphan": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Make an orphan Vault token",
			},

			"renewable": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Make token renewable",
			},

			"period": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Make token periodic",
			},

			"wrap": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    true,
				Description: "Wrap Vault token",
			},

			"wrap_ttl": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "1h",
				ForceNew:    true,
				Description: "TTL for wrapped token",
			},

			"no_default_policy": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    true,
				Description: "Do not include default policy",
			},

			"token": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Returned Vault token",
			},

			"accessor": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Returned Vault token accessor",
			},
		},
	}
}

func tokenCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(*api.Client)
	var (
		token *api.Secret
		err   error
	)

	wrap := d.Get("wrap")
	if wrap.(bool) {
		prevWrapTTLEnv := os.Getenv("VAULT_WRAP_TTL")
		os.Setenv("VAULT_WRAP_TTL", d.Get("wrap_ttl").(string))
		defer os.Setenv("VAULT_WRAP_TTL", prevWrapTTLEnv)
	}

	options := &api.TokenCreateRequest{
		DisplayName:     d.Get("display_name").(string),
		TTL:             d.Get("ttl").(string),
		ExplicitMaxTTL:  d.Get("explicit_max_ttl").(string),
		NoParent:        d.Get("orphan").(bool),
		NoDefaultPolicy: d.Get("no_default_policy").(bool),
	}

	r := d.Get("renewable").(bool)
	options.Renewable = &r

	if p, ok := d.GetOk("period"); ok {
		options.Period = p.(string)
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

	if role, ok := d.GetOk("role"); ok {
		token, err = client.Auth().Token().CreateWithRole(options, role.(string))
	} else {
		token, err = client.Auth().Token().Create(options)
	}
	if err != nil {
		return fmt.Errorf("error creating token: %v", err)
	}

	if wrap.(bool) {
		d.Set("token", token.WrapInfo.Token)
		d.Set("accessor", token.WrapInfo.WrappedAccessor)
		d.SetId(token.WrapInfo.WrappedAccessor)
	} else {
		d.Set("token", token.Auth.ClientToken)
		d.Set("accessor", token.Auth.Accessor)
		d.SetId(token.Auth.Accessor)
	}

	return nil
}

func tokenRead(d *schema.ResourceData, m interface{}) error {
	client := m.(*api.Client)

	_, err := client.Auth().Token().LookupAccessor(d.Id())
	if err != nil {
		// If we get a bad token error, it has likely been revoked
		// we will therefore remove token from state file
		if strings.HasSuffix(err.Error(), "bad token") {
			d.SetId("")
		}
		return fmt.Errorf("error reading accessor: %v", err)
	}

	return nil
}

func tokenDelete(d *schema.ResourceData, m interface{}) error {
	client := m.(*api.Client)

	if err := client.Auth().Token().RevokeAccessor(d.Id()); err != nil {
		// If we get a bad token error, it has likely been revoked
		// we will therefore remove token from state file
		if strings.HasSuffix(err.Error(), "bad token") {
			d.SetId("")
		}
		return fmt.Errorf("Error revoking token: %v", err)
	}

	return nil
}
