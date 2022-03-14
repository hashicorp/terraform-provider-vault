package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOIDCClientPathPrefix = "identity/oidc/client"

func identityOIDCClientResource() *schema.Resource {
	return &schema.Resource{
		Create: identityOIDCClientCreateUpdate,
		Update: identityOIDCClientCreateUpdate,
		Read:   identityOIDCClientRead,
		Delete: identityOIDCClientDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Description: "The name of the client.",
				Required:    true,
			},
			"key": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Description: "A reference to a named key resource in Vault. This cannot be modified after creation.",
				Required:    true,
			},
			"redirect_uris": {
				Type: schema.TypeSet,
				Description: "Redirection URI values used by the client. One of these values must exactly match the " +
					"redirect_uri parameter value used in each authentication request.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"assignments": {
				Type:        schema.TypeSet,
				Description: "A list of assignment resources associated with the client.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"id_token_ttl": {
				Type: schema.TypeInt,
				Description: "The time-to-live for ID tokens obtained by the client. The value should be less than the " +
					"verification_ttl on the key.",
				Optional: true,
			},
			"access_token_ttl": {
				Type:        schema.TypeInt,
				Description: "The time-to-live for access tokens obtained by the client.",
				Optional:    true,
			},
			"client_id": {
				Type:        schema.TypeString,
				Description: "The Client ID computed by and returned from Vault.",
				Computed:    true,
			},
			"client_secret": {
				Type:        schema.TypeString,
				Description: "The Client Secret computed by and returned from Vault.",
				Computed:    true,
			},
		},
	}
}

func identityOIDCClientRequestData(d *schema.ResourceData) map[string]interface{} {
	fields := []string{"key", "redirect_uris", "assignments", "id_token_ttl", "access_token_ttl"}
	data := map[string]interface{}{}

	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			if k == "redirect_uris" || k == "assignments" {
				data[k] = v.(*schema.Set).List()
				continue
			}
			data[k] = v
		}
	}

	return data
}

func getOIDCClientPath(name string) string {
	return fmt.Sprintf("%s/%s", identityOIDCClientPathPrefix, name)
}

func identityOIDCClientCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := getOIDCClientPath(name)

	_, err := client.Logical().Write(path, identityOIDCClientRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing OIDC Client %s, err=%w", path, err)
	}

	log.Printf("[DEBUG] Wrote OIDC Client to %s", path)

	d.SetId(path)

	return identityOIDCClientRead(d, meta)
}

func identityOIDCClientRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading OIDC Client for %s", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading OIDC Client for %s: %s", path, err)
	}

	log.Printf("[DEBUG] Read OIDC Client for %s", path)
	if resp == nil {
		log.Printf("[WARN] OIDC Client %s not found, removing from state", path)
		d.SetId("")

		return nil
	}

	for _, k := range []string{"key", "redirect_uris", "assignments", "id_token_ttl", "access_token_ttl", "client_id", "client_secret"} {
		// v := resp.Data[k]
		// fmt.Print(v)
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on OIDC Client %q, err=%w", k, path, err)
		}
	}

	return nil
}

func identityOIDCClientDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting OIDC Client %s", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting OIDC Client %q", path)
	}

	log.Printf("[DEBUG] Deleted OIDC Client %q", path)

	return nil
}
