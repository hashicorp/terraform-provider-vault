package vault

import (
	"encoding/base64"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"
)

var (
	awsAuthBackendCertBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/config/certificate/.+$")
	awsAuthBackendCertNameFromPathRegex    = regexp.MustCompile("^auth/.+/config/certificate/(.+$)")
)

func awsAuthBackendCertResource() *schema.Resource {
	return &schema.Resource{
		Create: awsAuthBackendCertCreate,
		Read:   awsAuthBackendCertRead,
		Delete: awsAuthBackendCertDelete,
		Exists: awsAuthBackendCertExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"cert_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the certificate to configure.",
				ForceNew:    true,
			},
			"aws_public_cert": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Base64 encoded AWS Public key required to verify PKCS7 signature of the EC2 instance metadata.",
				ForceNew:    true,
			},
			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The type of document that can be verified using the certificate. Must be either \"pkcs7\" or \"identity\".",
				ForceNew:     true,
				Default:      "pkcs7",
				ValidateFunc: validation.StringInSlice([]string{"pkcs7", "identity"}, false),
			},
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "aws",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func awsAuthBackendCertCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	certType := d.Get("type").(string)
	publicCert := d.Get("aws_public_cert").(string)
	name := d.Get("cert_name").(string)

	path := awsAuthBackendCertPath(backend, name)

	log.Printf("[DEBUG] Writing cert %q to AWS auth backend", path)
	_, err := client.Logical().Write(path, map[string]interface{}{
		"aws_public_cert": publicCert,
		"type":            certType,
	})

	d.SetId(path)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error configuring AWS auth backend cert %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote cert %q to AWS auth backend", path)

	return awsAuthBackendCertRead(d, meta)
}

func awsAuthBackendCertRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	backend, err := awsAuthBackendCertBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for AWS auth backend cert: %s", path, err)
	}

	name, err := awsAuthBackendCertNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for AWS auth backend cert: %s", path, err)
	}

	log.Printf("[DEBUG] Reading cert %q from AWS auth backend", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading AWS auth backend cert %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read cert %q from AWS auth backend", path)
	if resp == nil {
		log.Printf("[WARN] AWS auth backend cert %q not found, removing it from state", path)
		d.SetId("")
		return nil
	}

	// the cert response gets back as undecoded base64
	// to keep it simple for people referencing the cert body
	// and make sure they get what they expect, we turn it back
	// into base64 before putting it in the state
	d.Set("aws_public_cert", base64.RawStdEncoding.EncodeToString([]byte(resp.Data["aws_public_cert"].(string))))
	d.Set("type", resp.Data["type"])
	d.Set("backend", backend)
	d.Set("cert_name", name)

	return nil
}

func awsAuthBackendCertDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Removing cert %q from AWS auth backend", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting AWS auth backend cert %q: %s", path, err)
	}
	log.Printf("[DEBUG] Removed cert %q from AWS auth backend", path)

	return nil
}

func awsAuthBackendCertExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking if cert %q exists in AWS auth backend", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of AWS auth backend cert %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if cert %q exists in AWS auth backend", path)
	return resp != nil, nil
}

func awsAuthBackendCertPath(backend, name string) string {
	return "auth/" + strings.Trim(backend, "/") + "/config/certificate/" + strings.Trim(name, "/")
}

func awsAuthBackendCertNameFromPath(path string) (string, error) {
	if !awsAuthBackendCertNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := awsAuthBackendCertNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func awsAuthBackendCertBackendFromPath(path string) (string, error) {
	if !awsAuthBackendCertBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := awsAuthBackendCertBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
