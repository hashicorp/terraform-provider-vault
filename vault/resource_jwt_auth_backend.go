package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

var jwtAuthType = "jwt"

func jwtAuthBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: jwtAuthBackendWrite,
		Delete: jwtAuthBackendDelete,
		Read:   jwtAuthBackendRead,
		Update: jwtAuthBackendUpdate,

		Schema: map[string]*schema.Schema{

			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "path to mount the backend",
				Default:     jwtAuthType,
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, errors.New("cannot write to a path ending in '/'"))
					}
					return
				},
			},

			"description": {
				Type:        schema.TypeString,
				Required:    false,
				ForceNew:    true,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"oidc_discovery_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The OIDC Discovery URL, without any .well-known component (base path)",
			},

			"oidc_discovery_ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used",
			},

			"jwt_validation_pubkeys": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "A list of PEM-encoded public keys to use to authenticate signatures locally",
			},

			"bound_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value against which to match the iss claim in a JWT",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the JWT auth backend",
			},

		},
	}
}

func jwtAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	authType := jwtAuthType
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

	if backend == nil{
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
	d.Set("oidc_discovery_ca_pem", config.Data["oidc_discovery_ca_pem"])
	d.Set("bound_issuer", config.Data["bound_issuer"])
	d.Set("oidc_discovery_url", config.Data["oidc_discovery_url"])
	d.Set("jwt_validation_pubkeys", config.Data["jwt_validation_pubkeys"])

	return nil

}

func jwtAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := getJwtPath(d)
	log.Printf("[DEBUG] Updating auth %s in Vault", path)

	configuration := map[string]interface{}{
		"oidc_discovery_ca_pem": d.Get("oidc_discovery_ca_pem"),
		"bound_issuer":          d.Get("bound_issuer"),
	}

	oidcDiscoveryUrl, oidcDiscoveryUrlExists := d.GetOk("oidc_discovery_url")
	jwtValidationPubKeys, jwtValidationPubKeysExists := d.GetOk("jwt_validation_pubkeys")

	if oidcDiscoveryUrlExists == jwtValidationPubKeysExists {
		return errors.New("exactly one of oidc_discovery_url and jwt_validation_pubkeys should be provided")
	}

	if oidcDiscoveryUrlExists {
		configuration["oidc_discovery_url"] = oidcDiscoveryUrl
	}

	if jwtValidationPubKeysExists {
		configuration["jwt_validation_pubkeys"] = jwtValidationPubKeys
	}

	_, err := client.Logical().Write(jwtConfigEndpoint(path), configuration)
	if err != nil {
		return fmt.Errorf("error updating configuration to Vault for path %s: %s", path, err)
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

		if auth.Type == jwtAuthType && authBackendPath == configuredPath {
			return auth, nil
		}
	}

	return nil, nil
}

func getJwtPath(d *schema.ResourceData) string {
	return d.Get("path").(string)
}
