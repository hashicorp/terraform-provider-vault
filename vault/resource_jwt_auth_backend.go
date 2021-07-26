package vault

import (
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/hashicorp/vault/api"
)

func jwtAuthBackendResource() *schema.Resource {
	return &schema.Resource{
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Create: jwtAuthBackendWrite,
		Delete: jwtAuthBackendDelete,
		Read:   jwtAuthBackendRead,
		Update: jwtAuthBackendUpdate,

		CustomizeDiff: jwtCustomizeDiff,

		SchemaVersion: 1,
		Schema: map[string]*schema.Schema{

			"path": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Description:  "path to mount the backend",
				Default:      "jwt",
				ValidateFunc: validateNoTrailingSlash,
			},

			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Description:  "Type of backend. Can be either 'jwt' or 'oidc'",
				Default:      "jwt",
				ValidateFunc: validation.StringInSlice([]string{"jwt", "oidc"}, false),
			},

			"description": {
				Type:        schema.TypeString,
				Required:    false,
				ForceNew:    true,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"oidc_discovery_url": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"jwks_url", "jwt_validation_pubkeys"},
				Description:   "The OIDC Discovery URL, without any .well-known component (base path). Cannot be used with 'jwks_url' or 'jwt_validation_pubkeys'.",
			},

			"oidc_discovery_ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used",
			},

			"oidc_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client ID used for OIDC",
			},

			"oidc_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Client Secret used for OIDC",
			},

			"jwks_url": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"oidc_discovery_url", "jwt_validation_pubkeys"},
				Description:   "JWKS URL to use to authenticate signatures. Cannot be used with 'oidc_discovery_url' or 'jwt_validation_pubkeys'.",
			},

			"jwks_ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.",
			},

			"jwt_validation_pubkeys": {
				Type:          schema.TypeList,
				Elem:          &schema.Schema{Type: schema.TypeString},
				Optional:      true,
				ConflictsWith: []string{"jwks_url", "oidc_discovery_url"},
				Description:   "A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with 'jwks_url' or 'oidc_discovery_url'. ",
			},

			"bound_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value against which to match the iss claim in a JWT",
			},

			"jwt_supported_algs": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "A list of supported signing algorithms. Defaults to [RS256]",
			},

			"default_role": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The default role to use if none is provided during login",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the JWT auth backend",
			},
			"provider_config": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Provider specific handling configuration",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"tune": authMountTuneSchema(),
		},
		StateUpgraders: []schema.StateUpgrader{
			{
				Type:    resourceJwtAuthResourceV0().CoreConfigSchema().ImpliedType(),
				Upgrade: resourceJwtAuthStateUpgradeV0,
				Version: 0,
			},
		},
	}
}

func resourceJwtAuthResourceV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Description:  "path to mount the backend",
				Default:      "jwt",
				ValidateFunc: validateNoTrailingSlash,
			},

			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Description:  "Type of backend. Can be either 'jwt' or 'oidc'",
				Default:      "jwt",
				ValidateFunc: validation.StringInSlice([]string{"jwt", "oidc"}, false),
			},

			"description": {
				Type:        schema.TypeString,
				Required:    false,
				ForceNew:    true,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"oidc_discovery_url": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"jwks_url", "jwt_validation_pubkeys"},
				Description:   "The OIDC Discovery URL, without any .well-known component (base path). Cannot be used with 'jwks_url' or 'jwt_validation_pubkeys'.",
			},

			"oidc_discovery_ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used",
			},

			"oidc_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client ID used for OIDC",
			},

			"oidc_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Client Secret used for OIDC",
			},

			"jwks_url": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"oidc_discovery_url", "jwt_validation_pubkeys"},
				Description:   "JWKS URL to use to authenticate signatures. Cannot be used with 'oidc_discovery_url' or 'jwt_validation_pubkeys'.",
			},

			"jwks_ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.",
			},

			"jwt_validation_pubkeys": {
				Type:          schema.TypeList,
				Elem:          &schema.Schema{Type: schema.TypeString},
				Optional:      true,
				ConflictsWith: []string{"jwks_url", "oidc_discovery_url"},
				Description:   "A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with 'jwks_url' or 'oidc_discovery_url'. ",
			},

			"bound_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value against which to match the iss claim in a JWT",
			},

			"jwt_supported_algs": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "A list of supported signing algorithms. Defaults to [RS256]",
			},

			"default_role": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The default role to use if none is provided during login",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the JWT auth backend",
			},
			"provider_config": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Provider specific handling configuration",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"tune": authMountTuneSchema(),
		},
	}
}

func resourceJwtAuthStateUpgradeV0(rawState map[string]interface{}, meta interface{}) (map[string]interface{}, error) {

	// The provider_config schema changed types from TypeMap to
	// TypeSet, so we require a state upgrade. The values in this
	// schema are already strings, so we just need to convert the
	// non-string values.
	if rawConfig, ok := rawState["provider_config"]; ok {
		providerConfig := rawConfig.(map[string]interface{})
		var newConfig []map[string]interface{}
		newConfig = append(newConfig, providerConfig)

		if len(newConfig) != 1 {
			return rawState, fmt.Errorf("invalid length of provider_config during state upgrade")
		}

		if v, ok := providerConfig["fetch_groups"]; ok {
			valBool, err := strconv.ParseBool(v.(string))
			if err != nil {
				return rawState, fmt.Errorf("could not convert fetch_groups to bool: %s", err)
			}
			newConfig[0]["fetch_groups"] = valBool
		}

		if v, ok := providerConfig["fetch_user_info"]; ok {
			valBool, err := strconv.ParseBool(v.(string))
			if err != nil {
				return rawState, fmt.Errorf("could not convert fetch_user_info to bool: %s", err)
			}
			newConfig[0]["fetch_user_info"] = valBool
		}

		if v, ok := providerConfig["groups_recurse_max_depth"]; ok {
			valInt, err := strconv.ParseInt(v.(string), 10, 64)
			if err != nil {
				return rawState, fmt.Errorf("could not convert groups_recurse_max_depth to int: %s", err)
			}
			newConfig[0]["groups_recurse_max_depth"] = valInt
		}

		rawState["provider_config"] = newConfig
	}
	return rawState, nil
}

func jwtCustomizeDiff(d *schema.ResourceDiff, meta interface{}) error {
	attributes := []string{
		"oidc_discovery_url",
		"jwks_url",
		"jwt_validation_pubkeys",
		"provider_config",
	}

	for _, attr := range attributes {
		if !d.NewValueKnown(attr) {
			return nil
		}

		if _, ok := d.GetOk(attr); ok {
			return nil
		}
	}

	return errors.New("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided")
}

var (
	// TODO: build this from the Resource Schema?
	matchingJwtMountConfigOptions = []string{
		"oidc_discovery_url",
		"oidc_discovery_ca_pem",
		"oidc_client_id",
		"oidc_client_secret",
		"jwks_url",
		"jwks_ca_pem",
		"jwt_validation_pubkeys",
		"bound_issuer",
		"jwt_supported_algs",
		"default_role",
		"provider_config",
	}
)

func jwtAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	authType := d.Get("type").(string)
	desc := d.Get("description").(string)
	path := getJwtPath(d)

	log.Printf("[DEBUG] Writing auth %s to Vault", authType)

	err := client.Sys().EnableAuth(path, authType, desc)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return jwtAuthBackendUpdate(d, meta)
}

func jwtAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := getJwtPath(d)

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	err := client.Sys().DisableAuth(path)

	if err != nil {
		return fmt.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func jwtAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := getJwtPath(d)
	log.Printf("[DEBUG] Reading auth %s from Vault", path)

	if path == "" {
		// In v2.11.0 and prior, path was not read and so not set in the state.
		// if path is empty here, we're likely in a import scenario where path is
		// empty. Because path is used as the ID in the resource, if path is empty
		// use the ID value
		path = d.Id()
	}
	d.Set("path", path)

	backend, err := getJwtAuthBackendIfPresent(client, path)

	if err != nil {
		return fmt.Errorf("unable to check auth backends in Vault for path %s: %s", path, err)
	}

	if backend == nil {
		// If we fell out here then we didn't find our Auth in the list.
		d.SetId("")
		return nil
	}

	config, err := client.Logical().Read(jwtConfigEndpoint(path))

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	if config == nil {
		log.Printf("[WARN] JWT auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("type", backend.Type)

	d.Set("accessor", backend.Accessor)
	for _, configOption := range matchingJwtMountConfigOptions {
		// The oidc_client_secret is sensitive so it will not be in the response
		// Our options are to always assume it must be updated or always assume it
		//  matches our current state. This assumes it always matches our current
		//  state so that HasChange isn't always true and we store the last applied
		//  secret in the state file to know if the new secret should be applied.
		// This does intentionally miss the edge case where the oidc_client_secret
		//  is updated without Terraform. Since we cannot know the current state
		//  of the oidc_secret, Terraform will show no changes necessary even if
		//  the actual value in Vault does not match the value in state.
		if configOption == "oidc_client_secret" {
			continue
		}
		d.Set(configOption, config.Data[configOption])
	}

	log.Printf("[DEBUG] Reading jwt auth tune from %q", path+"/tune")
	rawTune, err := authMountTuneGet(client, "auth/"+path)
	if err != nil {
		return fmt.Errorf("error reading tune information from Vault: %s", err)
	}
	if err := d.Set("tune", []map[string]interface{}{rawTune}); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path %q to state: %s", path+"/tune", err)
		return err
	}

	return nil

}

func jwtAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := getJwtPath(d)
	log.Printf("[DEBUG] Updating auth %s in Vault", path)

	configuration := map[string]interface{}{}
	for _, configOption := range matchingJwtMountConfigOptions {
		// Set the configuration if the user has specified it, or the attribute is in the Diff
		if _, ok := d.GetOkExists(configOption); ok || d.HasChange(configOption) {
			configuration[configOption] = d.Get(configOption)
		}
	}

	_, err := client.Logical().Write(jwtConfigEndpoint(path), configuration)
	if err != nil {
		return fmt.Errorf("error updating configuration to Vault for path %s: %s", path, err)
	}

	if d.HasChange("tune") {
		log.Printf("[INFO] JWT/OIDC Auth '%q' tune configuration changed", d.Id())
		if raw, ok := d.GetOk("tune"); ok {
			backendType := d.Get("type")
			log.Printf("[DEBUG] Writing %s auth tune to '%q'", backendType, path)

			err := authMountTune(client, "auth/"+path, raw)
			if err != nil {
				return nil
			}

			log.Printf("[INFO] Written %s auth tune to %q", backendType, path)
			d.SetPartial("tune")
		}
	}

	return jwtAuthBackendRead(d, meta)
}

func jwtConfigEndpoint(path string) string {
	return fmt.Sprintf("/auth/%s/config", path)
}

func getJwtAuthBackendIfPresent(client *api.Client, path string) (*api.AuthMount, error) {
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

func getJwtPath(d *schema.ResourceData) string {
	return d.Get("path").(string)
}
