package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/vault/api"
)

func awsAuthBackendRoleTagResource() *schema.Resource {
	return &schema.Resource{
		Create: awsAuthBackendRoleTagResourceCreate,
		Read:   awsAuthBackendRoleTagResourceRead,
		Delete: awsAuthBackendRoleTagResourceDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "aws",
				Description: "AWS auth backend to read tags from.",
				ForceNew:    true,
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role.",
				ForceNew:    true,
			},
			"policies": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Policies to be associated with the tag.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew: true,
			},
			"max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
				ForceNew:    true,
			},
			"instance_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Instance ID for which this tag is intended. The created tag can only be used by the instance with the given ID.",
				ForceNew:    true,
			},
			"allow_instance_migration": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Allows migration of the underlying instance where the client resides.",
				ForceNew:    true,
			},
			"disallow_reauthentication": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Only allow a single token to be granted per instance ID.",
				ForceNew:    true,
			},
			"tag_value": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tag_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func awsAuthBackendRoleTagResourceCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	path := "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/") + "/tag"

	data := map[string]interface{}{}

	if v, ok := d.GetOk("policies"); ok {
		data["policies"] = v.(*schema.Set).List()
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v
	}
	if v, ok := d.GetOk("instance_id"); ok {
		data["instance_id"] = v
	}
	if v, ok := d.GetOk("allow_instance_migration"); ok {
		data["allow_instance_migration"] = v
	}
	if v, ok := d.GetOk("disallow_reauthentication"); ok {
		data["disallow_reauthentication"] = v
	}

	log.Printf("[DEBUG] Reading tag data %q from Vault", path)
	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error reading tag data %q from Vault: %s", path, err)
	}
	log.Printf("[DEBUG] Read tag data %q from Vault", path)

	d.SetId(secret.RequestID)
	d.Set("tag_value", secret.Data["tag_value"])
	d.Set("tag_key", secret.Data["tag_key"])

	return nil
}

func awsAuthBackendRoleTagResourceRead(d *schema.ResourceData, meta interface{}) error {
	// no read API call, this is only a resource to avoid nonces regenerating
	// on every refresh
	return nil
}

func awsAuthBackendRoleTagResourceDelete(d *schema.ResourceData, meta interface{}) error {
	// no delete API call, this is only a resource to avoid nonces regenerating
	// on every refresh
	return nil
}
