package vault

import (
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/hashicorp/vault/api"
)

func jwtAuthBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: jwtAuthBackendWrite,
		Delete: jwtAuthBackendDelete,
		Read:   jwtAuthBackendRead,
		Update: jwtAuthBackendUpdate,

		CustomizeDiff: jwtCustomizeDiff,

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
			"tune": authMountTuneSchema(),
		},
	}
}

func jwtCustomizeDiff(d *schema.ResourceDiff, meta interface{}) error {
	var _ interface{}
	var discUrlExists, jwksUrlExists, jwtPubKeysExists bool
	_, discUrlExists = d.GetOk("oidc_discovery_url")
	_, jwksUrlExists = d.GetOk("jwks_url")
	_, jwtPubKeysExists = d.GetOk("jwt_validation_pubkeys")

	if !(discUrlExists || jwksUrlExists || jwtPubKeysExists) {
		return errors.New("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided")
	}

	return nil
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

	d.Set("accessor", backend.Accessor)
	for _, configOption := range matchingJwtMountConfigOptions {
		d.Set(configOption, config.Data[configOption])
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

			log.Printf("[INFO] Written %s auth tune to '%q'", backendType, path)
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
