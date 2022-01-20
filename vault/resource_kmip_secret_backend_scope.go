package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func kmipSecretBackendScopeResource() *schema.Resource {
	return &schema.Resource{
		Create: kmipSecretBackendScopeCreate,
		Read:   kmipSecretBackendScopeRead,
		Update: kmipSecretBackendScopeUpdate,
		Delete: kmipSecretBackendScopeDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path where KMIP backend is mounted",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"scope": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the scope",
			},
		},
	}
}

func kmipSecretBackendScopeCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	scope := d.Get("scope").(string)

	data := map[string]interface{}{}
	if v, ok := d.GetOk("scope"); ok {
		data["scope"] = v.(string)
	}
	scopePath := path + "/scope/" + scope
	log.Printf("[DEBUG] Updating %q", scopePath)
	if _, err := client.Logical().Write(scopePath, data); err != nil {
		return fmt.Errorf("error updating KMIP config %q: %s", scopePath, err)
	}
	d.SetId(path)
	d.Set("scope", scope)
	return kmipSecretBackendScopeRead(d, meta)
}

func kmipSecretBackendScopeRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading KMIP scope at %q", path+"/scope")
	resp, err := client.Logical().List(path + "/scope")
	if err != nil {
		return fmt.Errorf("error reading KMIP scopes at %s: %s", path+"/scope", err)
	}
	if resp == nil {
		log.Printf("[WARN] KMIP scopes not found, removing from state")
		d.SetId("")
		// TODO Confirm this behavior
		d.Set("scope", "")
		return fmt.Errorf("expected scopes at %s, no scopes found", path+"/scope")
	}
	scopes := resp.Data["keys"].([]interface{})
	expectedScope := d.Get("scope")
	found := false
	for _, s := range scopes {
		if s.(string) == expectedScope {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("expected scope %s in list of scopes %s", expectedScope, scopes)
	}
	return nil
}

func kmipSecretBackendScopeUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()
	scope := d.Get("scope").(string)

	scopePath := path + "/scope/" + scope
	data := map[string]interface{}{}
	log.Printf("[DEBUG] Updating %q", scopePath)

	for _, k := range []string{"scope, force"} {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}
	if _, err := client.Logical().Write(scopePath, data); err != nil {
		return fmt.Errorf("error updating KMIP config %q: %s", scopePath, err)
	}
	log.Printf("[DEBUG] Updated %q", scopePath)

	return kmipSecretBackendScopeRead(d, meta)
}

func kmipSecretBackendScopeDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()
	scope := d.Get("scope").(string)

	scopePath := path + "/scope/" + scope
	log.Printf("[DEBUG] Deleting KMIP scope %q", scopePath)
	_, err := client.Logical().Delete(scopePath)
	if err != nil {
		return fmt.Errorf("error deleting scope %q", scopePath)
	}
	log.Printf("[DEBUG] Deleted KMIP scope %q", scopePath)

	return nil
}
