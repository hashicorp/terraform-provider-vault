package vault

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/hashicorp/vault/api"
)

func awsAuthBackendLoginResource() *schema.Resource {
	return &schema.Resource{
		Create: awsAuthBackendLoginCreate,
		Read:   awsAuthBackendLoginRead,
		Delete: awsAuthBackendLoginDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS Auth Backend to read the token from.",
				ForceNew:    true,
			},
			"role": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "AWS Auth Role to read the token from.",
				ForceNew:    true,
			},

			"identity": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base64-encoded EC2 instance identity document to authenticate with.",
				ForceNew:    true,
			},

			"signature": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base64-encoded SHA256 RSA signature of the instance identtiy document to authenticate with.",
				ForceNew:    true,
			},

			"pkcs7": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PKCS7 signature of the identity document to authenticate with, with all newline characters removed.",
				ForceNew:    true,
			},

			"nonce": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The nonce to be used for subsequent login requests.",
				Computed:    true,
				ForceNew:    true,
			},

			"iam_http_request_method": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The HTTP method used in the signed request.",
				ForceNew:    true,
			},

			"iam_request_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Base64-encoded HTTP URL used in the signed request.",
				ForceNew:    true,
			},

			"iam_request_body": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Base64-encoded body of the signed request.",
				ForceNew:    true,
			},

			"iam_request_headers": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Base64-encoded, JSON serialized representation of the sts:GetCallerIdentity HTTP request headers.",
				ForceNew:    true,
			},

			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},

			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},

			"renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},

			"metadata": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "The metadata reported by the Vault server.",
				Elem:        schema.TypeString,
			},

			"auth_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The auth method used to generate this token.",
			},

			"policies": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The policies assigned to this token.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor returned from Vault for this token.",
			},

			"client_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The token returned by Vault.",
				Sensitive:   true,
			},
		},
	}
}

func awsAuthBackendLoginCreate(d *schema.ResourceData, meta interface{}) error {
	return awsAuthBackendLoginRead(d, meta)
}

func awsAuthBackendLoginRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := strings.Trim(d.Get("backend").(string), "/")
	path := "auth/" + backend + "/login"

	data := map[string]interface{}{}

	if v, ok := d.GetOk("role"); ok {
		data["role"] = v
	}

	if v, ok := d.GetOk("identity"); ok {
		data["identity"] = v
	}

	if v, ok := d.GetOk("signature"); ok {
		data["signature"] = v
	}

	if v, ok := d.GetOk("pkcs7"); ok {
		data["pkcs7"] = v
	}

	if v, ok := d.GetOk("nonce"); ok {
		data["nonce"] = v
	}

	if v, ok := d.GetOk("iam_http_request_method"); ok {
		data["iam_http_request_method"] = v
	}

	if v, ok := d.GetOk("iam_request_url"); ok {
		data["iam_request_url"] = v
	}

	if v, ok := d.GetOk("iam_request_body"); ok {
		data["iam_request_body"] = v
	}

	if v, ok := d.GetOk("iam_request_headers"); ok {
		data["iam_request_headers"] = v
	}

	log.Printf("[DEBUG] Reading %q from Vault", path)
	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	id := "accessor:" + secret.Auth.Accessor
	nonce, ok := secret.Auth.Metadata["nonce"]
	if ok {
		// when nonce is set, prefer that over accessor
		// as instances can only auth once every so often and
		// need the nonce to return the token, so if we ever
		// want to support import, we can just import the nonce
		// and use that.
		//
		// however, when using iam auth, the nonce isn't set, so
		// we can't use that solely as the identifier
		//
		// to help keep things straight, we prefix with the type of
		// ID that's actually set
		id = "nonce:" + nonce
		d.Set("nonce", nonce)
	}
	d.SetId(id)
	d.Set("lease_duration", secret.Auth.LeaseDuration)
	d.Set("lease_start_time", time.Now().Format(time.RFC3339))
	d.Set("renewable", secret.Auth.Renewable)
	d.Set("metadata", secret.Auth.Metadata)
	d.Set("policies", secret.Auth.Policies)
	d.Set("accessor", secret.Auth.Accessor)
	d.Set("client_token", secret.Auth.ClientToken)

	return nil
}

func awsAuthBackendLoginDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	accessor := d.Get("accessor").(string)
	token, ok := d.GetOk("client_token")
	if !ok {
		log.Printf("[DEBUG] Token %q has no token set in state, removing from state", accessor)
		return nil
	}
	log.Printf("[DEBUG] Revoking token %q", accessor)
	err := client.Auth().Token().RevokeTree(token.(string))
	if err != nil {
		log.Printf("[ERROR] Error revoking token %q: %s", accessor, err)
		return err
	}
	log.Printf("[DEBUG] Revoked token %q", accessor)
	return nil
}
