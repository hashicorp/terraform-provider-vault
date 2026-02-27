// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const defaultKeyTypeSSH = "ssh-rsa"

func sshSecretBackendCAResource() *schema.Resource {
	return &schema.Resource{
		Create: sshSecretBackendCACreate,
		Read:   provider.ReadWrapper(sshSecretBackendCARead),
		Delete: sshSecretBackendCADelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		SchemaVersion: 1,
		StateUpgraders: []schema.StateUpgrader{
			{
				Version: 0,
				Type:    sshSecretBackendCAResourceV0().CoreConfigSchema().ImpliedType(),
				Upgrade: sshSecretBackendCAUpgradeV0,
			},
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "ssh",
				ForceNew:    true,
				Description: "The path of the SSH Secret Backend where the CA should be configured",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"generate_signing_key": {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Description: "Whether Vault should generate the signing key pair internally.",
			},
			"key_type": {
				Type:        schema.TypeString,
				Default:     defaultKeyTypeSSH,
				Optional:    true,
				ForceNew:    true,
				Description: "Specifies the desired key type for the generated SSH CA key when `generate_signing_key` is set to `true`.",
			},
			"key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Description: "Specifies the desired key bits for the generated SSH CA key when `generate_signing_key` is set to `true`.",
			},
			"managed_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The name of the managed key to use. When using a managed key, this field or managed_key_id is required.",
			},
			"managed_key_id": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The id of the managed key to use. When using a managed key, this field or managed_key_name is required.",
			},
			"private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Sensitive:   true,
				Computed:    true,
				Description: "Private key part the SSH CA key pair; required if generate_signing_key is false.",
			},
			"public_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Public key part the SSH CA key pair; required if generate_signing_key is false.",
			},
		},
	}
}

func sshSecretBackendCACreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)

	data := make(map[string]interface{})
	if generateSigningKey, ok := d.Get("generate_signing_key").(bool); ok {
		data["generate_signing_key"] = generateSigningKey
	}
	if privateKey, ok := d.Get("private_key").(string); ok {
		data["private_key"] = privateKey
	}
	if publicKey, ok := d.Get("public_key").(string); ok {
		data["public_key"] = publicKey
	}
	if keyType, ok := d.Get("key_type").(string); ok {
		data["key_type"] = keyType
	}
	if keyBits, ok := d.Get("key_bits").(int); ok {
		data["key_bits"] = keyBits
	}

	if provider.IsAPISupported(meta, provider.VaultVersion120) {
		if managedKeyName, ok := d.Get("managed_key_name").(string); ok {
			data["managed_key_name"] = managedKeyName
		}
		if managedKeyId, ok := d.Get("managed_key_id").(string); ok {
			data["managed_key_id"] = managedKeyId
		}
	}

	log.Printf("[DEBUG] Writing CA information on SSH backend %q", backend)
	_, err := client.Logical().Write(backend+"/config/ca", data)
	if err != nil {
		return fmt.Errorf("Error writing CA information for backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Written CA information on SSH backend %q", backend)

	d.SetId(backend)
	return sshSecretBackendCARead(d, meta)
}

func sshSecretBackendCARead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Id()

	log.Printf("[DEBUG] Reading CA information from SSH backend %q", backend)
	secret, err := client.Logical().Read(backend + "/config/ca")
	if err != nil {
		if apiRespErr, ok := err.(*api.ResponseError); ok {
			for _, e := range apiRespErr.Errors {
				if e == "keys haven't been configured yet" {
					log.Printf("[WARN] CA information not found in SSH backend %q, removing from state", backend)
					d.SetId("")
					return nil
				}
			}
		}
		return fmt.Errorf("Error reading CA information from SSH backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Read CA information from SSH backend %q", backend)
	if secret == nil {
		log.Printf("[WARN] CA information not found in SSH backend %q, removing from state", backend)
		d.SetId("")
		return nil
	}
	d.Set("public_key", secret.Data["public_key"])
	d.Set("backend", backend)

	// the API doesn't return private_key, generate_signing_key, key_type, or key_bits.
	// So... if they drift, they drift.

	return nil
}

func sshSecretBackendCADelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Id()
	log.Printf("[DEBUG] Deleting CA configuration for SSH backend %q", backend)
	_, err := client.Logical().Delete(backend + "/config/ca")
	if err != nil {
		return fmt.Errorf("Error deleting CA configuration for SSH backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Deleted CA configuration for SSH backend %q", backend)

	return nil
}

func sshSecretBackendCAResourceV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"key_type": {
				Type:        schema.TypeString,
				Default:     defaultKeyTypeSSH,
				Optional:    true,
				ForceNew:    true,
				Description: "Specifies the desired key type for the generated SSH CA key when `generate_signing_key` is set to `true`.",
			},
		},
	}
}

// sshSecretBackendCAUpgradeV0 allows update the state for the vault_ssh_secret_backend_ca
// resource that was provisioned with older schema configurations.
//
// Upgrading the Vault provider from 4.2.0 to 4.3.0 results in
// vault_ssh_secret_backend_ca being replaced although no other changes have
// been made. The key_type attribute, introduced in #1454, gets added
// (implicit, using the default value) and forces the resource to be replaced.
// See https://github.com/hashicorp/terraform-provider-vault/issues/2281
func sshSecretBackendCAUpgradeV0(_ context.Context, rawState map[string]interface{}, _ interface{}) (map[string]interface{}, error) {
	if rawState["key_type"] == nil {
		rawState["key_type"] = defaultKeyTypeSSH
	}

	return rawState, nil
}
