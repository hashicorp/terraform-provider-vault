package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func identityOidcKeyAllowedClientId() *schema.Resource {
	return &schema.Resource{
		Create: identityOidcKeyAllowedClientIdWrite,
		Read:   identityOidcKeyAllowedClientIdRead,
		Delete: identityOidcKeyAllowedClientIdDelete,

		Schema: map[string]*schema.Schema{
			"key_name": {
				Type:        schema.TypeString,
				Description: "Name of the key.",
				Required:    true,
				ForceNew:    true,
			},

			"allowed_client_id": {
				Type:        schema.TypeString,
				Description: "Role Client ID allowed to use the key for signing.",
				Required:    true,
				ForceNew:    true,
			},
		},
	}
}

func identityOidcKeyAllowedClientIdWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("key_name").(string)
	path := identityOidcKeyPath(name)
	clientID := d.Get("allowed_client_id").(string)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data, err := identityOidcKeyApiRead(name, client)
	if err != nil {
		return fmt.Errorf("error reading IdentityOidcKey %s: %s", name, err)
	}

	if data == nil {
		return fmt.Errorf("IdentityOidcKey %s not found", name)
	}

	log.Printf("[DEBUG] Adding allowed_client_id %s for IdentityOidcKey %s", clientID, name)
	d.SetId(identityOidcKeyAllowedClientIdStateId(name, clientID))
	clientIDs := data["allowed_client_ids"].([]interface{})
	clientIDs = util.SliceAppendIfMissing(clientIDs, clientID)

	err = identityOidcKeyApiWrite(name, map[string]interface{}{"allowed_client_ids": clientIDs}, client)
	if err != nil {
		return fmt.Errorf("error updating Allowed Client ID %s for key %s: %q", clientID, name, err)
	}

	log.Printf("[DEBUG] Added allowed_client_id %s for IdentityOidcKey %s", clientID, name)
	return identityOidcKeyAllowedClientIdRead(d, meta)
}

func identityOidcKeyAllowedClientIdRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("key_name").(string)
	clientID := d.Get("allowed_client_id").(string)

	data, err := identityOidcKeyApiRead(name, client)
	if err != nil {
		return fmt.Errorf("error reading IdentityOidcKey %s: %s", name, err)
	}

	if data == nil {
		log.Printf("[WARN] IdentityOidcKey %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	if found, _ := util.SliceHasElement(data["allowed_client_ids"].([]interface{}), clientID); !found {
		log.Printf("[WARN] IdentityOidcKey %s does not have allowed_client_ids %s, removing from state", name, clientID)
		d.SetId("")
		return nil
	}

	return nil
}

func identityOidcKeyAllowedClientIdDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("key_name").(string)
	path := identityOidcKeyPath(name)
	clientID := d.Get("allowed_client_id").(string)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data, err := identityOidcKeyApiRead(name, client)
	if err != nil {
		return fmt.Errorf("error reading IdentityOidcKey %s: %s", name, err)
	}

	if data == nil {
		// Key is gone. We can return
		return nil
	}

	clientIDs := data["allowed_client_ids"].([]interface{})
	clientIDs = util.SliceRemoveIfPresent(clientIDs, clientID)

	log.Printf("[DEBUG] Removing allowed_client_id %s for IdentityOidcKey %s", clientID, name)
	err = identityOidcKeyApiWrite(name, map[string]interface{}{"allowed_client_ids": clientIDs}, client)
	if err != nil {
		return fmt.Errorf("error removing Allowed Client ID %s for key %s: %q", clientID, name, err)
	}
	log.Printf("[DEBUG] Removed allowed_client_id %s for IdentityOidcKey %s", clientID, name)

	return nil
}

func identityOidcKeyAllowedClientIdStateId(key_name, clientID string) string {
	return fmt.Sprintf("%s/%s", key_name, clientID)
}
