package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"
)

func authMountTuneSchema() *schema.Schema {
	additionalFields := map[string]*schema.Schema{
		"token_type": {
			Type:         schema.TypeString,
			Optional:     true,
			Description:  "Specifies the type of tokens that should be returned by the mount.",
			ValidateFunc: validation.StringInSlice([]string{"default-service", "default-batch", "service", "batch"}, false),
		},
	}
	return sharedAuthAndMountSchema(additionalFields)
}

func authMountInfoGet(client *api.Client, path string) (*api.AuthMount, error) {
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return nil, fmt.Errorf("error reading from auth mounts: %s", err)
	}

	authMount := auths[strings.Trim(path, "/")+"/"]
	if authMount == nil {
		return nil, fmt.Errorf("auth mount %s not present", path)
	}
	return authMount, nil
}

func authMountTune(client *api.Client, path string, configured interface{}) error {
	tune := expandMountConfigInput(configured.(*schema.Set).List())

	err := client.Sys().TuneMount(path, tune)
	if err != nil {
		return err
	}
	return nil
}

func authMountConfigGet(client *api.Client, path string) (map[string]interface{}, error) {
	tune, err := client.Sys().MountConfig(path)
	if err != nil {
		log.Printf("[ERROR] Error when reading tune config from path %q: %s", path+"/tune", err)
		return nil, err
	}
	return flattenAuthMountConfig(tune), nil
}

func authMountDisable(client *api.Client, path string) error {
	log.Printf("[DEBUG] Disabling auth mount config from '%q'", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("error disabling auth mount from '%q': %s", path, err)
	}
	log.Printf("[INFO] Disabled auth mount from '%q'", path)

	return nil
}

func getAuthMountIfPresent(client *api.Client, path string) (*api.AuthMount, error) {
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return nil, fmt.Errorf("error reading from Vault: %s", err)
	}

	configuredPath := path + "/"

	for authBackendPath, auth := range auths {

		if authBackendPath == configuredPath {
			return auth, nil
		}
	}

	return nil, nil
}
