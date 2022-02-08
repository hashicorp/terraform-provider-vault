package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func kmipSecretScopeResource() *schema.Resource {
	return &schema.Resource{
		Create: kmipSecretScopeCreate,
		Read:   kmipSecretScopeRead,
		Update: kmipSecretScopeUpdate,
		Delete: kmipSecretScopeDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where KMIP backend is mounted",
				ValidateFunc: validateNoTrailingLeadingSlashes,
			},
			"scope": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the scope",
			},
			"force": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Force deletion even if there are managed objects in the scope",
			},
		},
	}
}

func kmipSecretScopeCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	scope := d.Get("scope").(string)
	force := d.Get("force").(bool)

	data := map[string]interface{}{
		"scope": scope,
		"force": force,
	}

	scopePath := path + "/scope/" + scope
	log.Printf("[DEBUG] Updating %q", scopePath)
	if _, err := client.Logical().Write(scopePath, data); err != nil {
		return fmt.Errorf("error updating KMIP scope %s: %s", scopePath, err)
	}
	d.SetId(scopePath)
	if err := d.Set("scope", scope); err != nil {
		return err
	}

	return kmipSecretScopeRead(d, meta)
}

func kmipSecretScopeRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	expectedScope := d.Get("scope").(string)

	log.Printf("[DEBUG] Reading KMIP scope at %s", path+"/scope")
	configured, err := isScopeConfigured(client, path+"/scope", expectedScope)
	if !configured {
		log.Printf("[WARN] KMIP scopes not found, removing from state")
		d.SetId("")
		return err
	}

	return nil
}

func kmipSecretScopeUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	scope := d.Get("scope").(string)

	if d.HasChange("path") {
		newMountPath := d.Get("path").(string)
		log.Printf("[DEBUG] Confirming KMIP scope exists at %s", newMountPath+"/scope")
		configured, err := isScopeConfigured(client, newMountPath+"/scope", scope)
		if !configured {
			return fmt.Errorf("error remounting KMIP scope to new backend path %s, err=%w", newMountPath+"/scope", err)
		}
		d.SetId(newMountPath + "/scope/" + scope)
	}

	return kmipSecretScopeRead(d, meta)
}

func kmipSecretScopeDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	scopePath := d.Id()

	log.Printf("[DEBUG] Deleting KMIP scope %q", scopePath)
	_, err := client.Logical().Delete(scopePath)
	if err != nil {
		return fmt.Errorf("error deleting scope %q", scopePath)
	}
	log.Printf("[DEBUG] Deleted KMIP scope %q", scopePath)

	return nil
}

func isScopeConfigured(client *api.Client, path, name string) (bool, error) {
	resp, err := client.Logical().List(path)
	if err != nil {
		return false, fmt.Errorf("error reading KMIP scopes at %s: %s", path, err)
	}
	if resp == nil {
		return false, fmt.Errorf("expected scopes at %s, no scopes found", path)
	}

	var scopes []interface{}
	if v, ok := resp.Data["keys"].([]interface{}); ok && v != nil {
		scopes = v
	}
	found := false
	for _, s := range scopes {
		if s.(string) == name {
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("expected scope %s in list of scopes %s", name, scopes)
	}

	return true, nil
}
