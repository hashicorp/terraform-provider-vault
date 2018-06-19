package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func kubernetesAuthBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: kubernetesAuthBackendCreate,
		Read:   kubernetesAuthBackendRead,
		Update: kubernetesAuthBackendUpdate,
		Delete: kubernetesAuthBackendDelete,
		Exists: kubernetesAuthBackendExists,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Path to mount the backend",
				Default:     "kubernetes",
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
				Optional:    true,
				ForceNew:    true,
				Description: "The description of the auth backend",
			},

			"host": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URL for the Kubernetes API server",
			},

			"ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PEM encoded CA cert for use by the TLS client.",
			},

			"token_reviewer_jwt": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A service account JWT used to access the TokenReview API.",
			},

			"pem_keys": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "PEM encoded public keys or certificates to verify service account JWTs.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func kubernetesAuthBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	desc := d.Get("description").(string)

	log.Printf("[DEBUG] Writing Kubernetes auth backend %q", path)
	err := client.Sys().EnableAuth(path, "kubernetes", desc)
	if err != nil {
		return fmt.Errorf("Error writing Kubernetes auth backend %q: %s", path, err)
	}

	d.SetId(path)

	return kubernetesAuthBackendUpdate(d, meta)
}

func kubernetesAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading Kubernetes auth backend %q", path)
	config, err := readKubernetesConfig(client, path)
	if err != nil {
		return fmt.Errorf("Error reading Kubernetes auth backend %q: %s", path, err)
	}

	if config != nil {
		if err := d.Set("host", config.Host); err != nil {
			return err
		}
		if err := d.Set("ca_cert", config.CACert); err != nil {
			return err
		}
		if err := d.Set("token_reviewer_jwt", config.TokenReviewerJWT); err != nil {
			return err
		}
		if err := d.Set("pem_keys", config.PEMKeys); err != nil {
			return err
		}
	} else {
		// Resource does not exist, so clear ID
		d.SetId("")
	}

	return nil
}

func kubernetesAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	host := d.Get("host").(string)
	caCert := d.Get("ca_cert").(string)
	tokenReviewerJWT := d.Get("token_reviewer_jwt").(string)

	var pemKeysArray []string
	if pemKeys, ok := d.GetOk("pem_keys"); ok {
		pemKeysArray = toStringArray(pemKeys.(*schema.Set).List())
	} else {
		pemKeysArray = []string{}
	}

	log.Printf("[DEBUG] Updating Kubernetes auth backend %q", path)
	if err := updateKubernetesConfig(client, path, kubernetesConfig{
		Host:             host,
		CACert:           caCert,
		TokenReviewerJWT: tokenReviewerJWT,
		PEMKeys:          pemKeysArray,
	}); err != nil {
		return fmt.Errorf("Error updating Kubernetes auth backend %q: %s", path, err)
	}

	return kubernetesAuthBackendRead(d, meta)
}

func kubernetesAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Disabling Kubernetes auth backend %q", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("Error disabling Kubernetes auth backend %q: %s", path, err)
	}

	return nil
}

func kubernetesAuthBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking if Kubernetes auth backend %q exists", path)
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return true, fmt.Errorf("Error checking if Kubernetes auth backend %q exists: %s", path, err)
	}

	for authPath, auth := range auths {
		if auth.Type == "kubernetes" && authPath == fmt.Sprintf("%s/", path) {
			return true, nil
		}
	}

	return false, nil
}
