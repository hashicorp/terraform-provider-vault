// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	transitSecretBackendKeyBackendFromPathRegex = regexp.MustCompile("^(.+)/keys/.+$")
	transitSecretBackendKeyNameFromPathRegex    = regexp.MustCompile("^.+/keys/(.+)$")
)

func transitSecretBackendKeyResource() *schema.Resource {
	return &schema.Resource{
		Create: transitSecretBackendKeyCreate,
		Read:   provider.ReadWrapper(transitSecretBackendKeyRead),
		Update: transitSecretBackendKeyUpdate,
		Delete: transitSecretBackendKeyDelete,
		Exists: transitSecretBackendKeyExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the resource belongs to.",
				ForceNew:    true,
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the encryption key to create.",
				ForceNew:    true,
			},
			"deletion_allowed": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies if the key is allowed to be deleted.",
				Default:     false,
			},
			"convergent_encryption": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether or not to support convergent encryption, where the same plaintext creates the same ciphertext. This requires derived to be set to true.",
				ForceNew:    true,
				Default:     false,
			},
			"derived": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies if key derivation is to be used. If enabled, all encrypt/decrypt requests to this key must provide a context which is used for key derivation.",
				ForceNew:    true,
				Default:     false,
			},
			"exportable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enables keys to be exportable. This allows for all the valid keys in the key ring to be exported. Once set, this cannot be disabled.",
				Default:     false,
			},
			"allow_plaintext_backup": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, enables taking backup of named key in the plaintext format. Once set, this cannot be disabled.",
				Default:     false,
			},
			"auto_rotate_interval": {
				Type:          schema.TypeInt,
				Optional:      true,
				Computed:      true,
				Deprecated:    "Use auto_rotate_period instead",
				Description:   "Amount of time the key should live before being automatically rotated. A value of 0 disables automatic rotation for the key.",
				ConflictsWith: []string{"auto_rotate_period"},
			},
			"auto_rotate_period": {
				Type:          schema.TypeInt,
				Optional:      true,
				Computed:      true,
				Description:   "Amount of seconds the key should live before being automatically rotated. A value of 0 disables automatic rotation for the key.",
				ConflictsWith: []string{"auto_rotate_interval"},
			},
			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Specifies the type of key to create. The currently-supported types are: aes128-gcm96, aes256-gcm96, chacha20-poly1305, ed25519, ecdsa-p256, ecdsa-p384, ecdsa-p521, hmac, rsa-2048, rsa-3072, rsa-4096",
				ForceNew:     true,
				Default:      "aes256-gcm96",
				ValidateFunc: validation.StringInSlice([]string{"aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "ed25519", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "hmac", "rsa-2048", "rsa-3072", "rsa-4096"}, false),
			},
			"keys": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of key versions in the keyring.",
				Elem: &schema.Schema{
					Type: schema.TypeMap,
					Elem: schema.TypeString,
				},
			},
			"key_size": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The key size in bytes for algorithms that allow variable key sizes. Currently only applicable to HMAC, where it must be between 32 and 512 bytes.",
				Default:     0,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(int)
					// Default for non-hmac is 0.
					if v == 0 || v < 32 || v > 512 {
						errs = append(errs, fmt.Errorf("%q must be greater than 32, and less than 512. Got: %d", key, v))
					}
					return
				},
			},
			"latest_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Latest key version in use in the keyring",
			},
			"min_available_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Minimum key version available for use.",
			},
			"min_decryption_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Minimum key version to use for decryption.",
				Default:     1,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(int)
					if v < 1 {
						errs = append(errs, fmt.Errorf("%q must be equal to or greater than 1, got: %d", key, v))
					}
					return
				},
			},
			"min_encryption_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Minimum key version to use for encryption",
				Default:     0,
			},
			"supports_encryption": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports encryption, based on key type.",
			},
			"supports_decryption": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports decryption, based on key type.",
			},
			"supports_derivation": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports derivation, based on key type.",
			},
			"supports_signing": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports signing, based on key type.",
			},
		},
		CustomizeDiff: customdiff.All(
			customdiff.ValidateChange("exportable", func(_ context.Context, old, new, meta interface{}) error {
				// 'exportable' Can only be enabled once, and once it is enabled, it cannot be disabled
				//   without creating a new key

				// new == true, old == false
				if new.(bool) && !old.(bool) {
					return nil
				}
				// new == false, old == true
				if !new.(bool) && old.(bool) {
					return fmt.Errorf("'exportable' cannot be disabled on a key that already has it enabled")
				}
				return nil
			}),
			customdiff.ValidateChange("allow_plaintext_backup", func(_ context.Context, old, new, meta interface{}) error {
				// Same conditions as above. This cannot be disabled once enabled.
				if new.(bool) && !old.(bool) {
					return nil
				}
				if !new.(bool) && old.(bool) {
					return fmt.Errorf("'allow_plaintext_backup' cannot be disabled on a key that already has it enabled")
				}
				return nil
			}),
			customdiff.ForceNewIfChange("exportable", func(_ context.Context, old, new, meta interface{}) bool {
				return !new.(bool) && old.(bool)
			}),
			customdiff.ForceNewIfChange("allow_plaintext_backup", func(_ context.Context, old, new, meta interface{}) bool {
				return !new.(bool) && old.(bool)
			}),
		),
	}
}

func transitSecretBackendKeyCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := transitSecretBackendKeyPath(backend, name)

	autoRotatePeriod := getTransitAutoRotatePeriod(d)
	configData := map[string]interface{}{
		"min_decryption_version": d.Get("min_decryption_version").(int),
		"min_encryption_versoin": d.Get("min_encryption_version").(int),
		"deletion_allowed":       d.Get("deletion_allowed").(bool),
		"exportable":             d.Get("exportable").(bool),
		"allow_plaintext_backup": d.Get("allow_plaintext_backup").(bool),
		"auto_rotate_period":     autoRotatePeriod,
	}

	data := map[string]interface{}{
		"convergent_encryption": d.Get("convergent_encryption").(bool),
		"derived":               d.Get("derived").(bool),
		"type":                  d.Get("type").(string),
		"auto_rotate_period":    autoRotatePeriod,
		"key_size":              d.Get("key_size").(int),
	}

	log.Printf("[DEBUG] Creating encryption key %s on transit secret backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating encryption key %s for transit secret backend %q: %s with key size %d", name, backend, err, d.Get("key_size").(int))
	}
	log.Printf("[DEBUG] Setting configuration for encryption key %s on transit secret backend %q", name, backend)
	_, conferr := client.Logical().Write(path+"/config", configData)
	if conferr != nil {
		return fmt.Errorf("error setting configuration for transit secret backend key %q: %s", path, conferr)
	}

	log.Printf("[DEBUG] Created encryption key %s on transit secret backend %q", name, backend)
	d.SetId(path)
	return transitSecretBackendKeyRead(d, meta)
}

func getTransitAutoRotatePeriod(d *schema.ResourceData) int {
	var autoRotatePeriod int
	v, ok := d.GetOkExists("auto_rotate_period")
	if !ok {
		if v, ok := d.GetOkExists("auto_rotate_interval"); ok {
			log.Printf("[WARN] Using auto_rotate_internal to set auto_rotate_period, " +
				"please use auto_rotate_period instead")
			autoRotatePeriod = v.(int)
		}
	} else {
		autoRotatePeriod = v.(int)
	}

	return autoRotatePeriod
}

func transitSecretBackendKeyRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	backend, err := transitSecretBackendKeyBackendFromPath(path)
	log.Printf("[DEBUG] reading from backend %s", backend)
	if err != nil {
		log.Printf("[WARN] Removing key %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid key ID %q: %s", path, err)
	}

	name, err := transitSecretBackendKeyNameFromPath(path)
	log.Printf("[DEBUG] reading key %s from backend %s", name, backend)
	if err != nil {
		log.Printf("[WARN] Removing key %q because its ID is invalid", path)
		d.SetId("")
		return fmt.Errorf("invalid roleID %q: %s", path, err)
	}

	log.Printf("[DEBUG] Reading key from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading key %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read key from %q", path)
	if secret == nil {
		log.Printf("[WARN] Key %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	// The vault API does not use "convergent_encryption" when the key type is not one of rsa-2048, rsa-3072, rsa-4096, ed25519, ecdsa-p256, ecdsa-p384 or ecdsa-p521
	iConvergentEncryption := secret.Data["convergent_encryption"]
	convergentEncryption := false
	if ce, ok := iConvergentEncryption.(bool); ok {
		convergentEncryption = ce
	}

	latestVersion, err := secret.Data["latest_version"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected latest_version %q to be a number, and it isn't", secret.Data["latest_version"])
	}

	minAvailableVersion, err := secret.Data["min_available_version"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected min_available_version %q to be a number, and it isn't", secret.Data["min_available_version"])
	}

	minDecryptionVersion, err := secret.Data["min_decryption_version"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected min_decryption_version %q to be a number, and it isn't", secret.Data["min_decryption_version"])
	}

	minEncryptionVersion, err := secret.Data["min_encryption_version"].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected min_encryption_version %q to be a number, and it isn't", secret.Data["min_encryption_version"])
	}

	ikeys := secret.Data["keys"]
	keys := []interface{}{}
	if ikeys != nil || secret.Data["type"] != "hmac" { // hmac type does not return keys
		ikeys := secret.Data["keys"].(map[string]interface{})
		for _, v := range ikeys {
			// Data structure of "keys" differs depending on encryption key type. Sometimes it's a single integer hash,
			// and other times it's a full map of values describing the key version's creation date, name, and public key.
			if sv, ok := v.(map[string]interface{}); ok { // for key types of rsa-2048, rsa-3072, rsa-4096, ed25519, ecdsa-p256, ecdsa-p384 or ecdsa-p521
				keys = append(keys, sv)
			} else if sv, ok := v.(json.Number); ok { // for key types of aes128-gcm96, aes256-gcm96 or chacha20-poly1305
				m := make(map[string]interface{})
				m["id"] = sv
				keys = append(keys, m)
			}
		}

	}

	if err := d.Set("keys", keys); err != nil {
		return err
	}

	// On read, key_size will be nil if the encryption key type is not HMAC. Choosing not to set it in those cases.
	key_size := secret.Data["key_size"]
	if key_size != nil || secret.Data["type"] == "hmac" {
		key_size, err := secret.Data["key_size"].(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("expected key_size %q to be a number, and it isn't", secret.Data["key_size"])
		}

		if key_size > 0 { // Just to make sure we are not creating an HMAC type key with a key_size of 0.
			if err := d.Set("key_size", key_size); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("expected key_size %q to be greater than zero, and it isn't", secret.Data["key_size"])
		}
	}

	if err := d.Set("backend", backend); err != nil {
		return err
	}
	if err := d.Set("name", name); err != nil {
		return err
	}
	if err := d.Set("latest_version", latestVersion); err != nil {
		return err
	}
	if err := d.Set("min_available_version", minAvailableVersion); err != nil {
		return err
	}
	if err := d.Set("min_decryption_version", minDecryptionVersion); err != nil {
		return err
	}
	if err := d.Set("min_encryption_version", minEncryptionVersion); err != nil {
		return err
	}
	if err := d.Set("convergent_encryption", convergentEncryption); err != nil {
		return err
	}

	fields := []string{
		"allow_plaintext_backup",
		"deletion_allowed", "derived", "exportable",
		"supports_decryption", "supports_derivation",
		"supports_encryption", "supports_signing", "type",
	}

	set := func(f, k string) error {
		v, ok := secret.Data[k]
		if !ok {
			log.Printf("[WARN] Expected key %q not found in response, path=%q", k, path)
		}
		if err := d.Set(f, v); err != nil {
			return err
		}
		return nil
	}

	for _, f := range fields {
		if err := set(f, f); err != nil {
			return err
		}
	}

	autoRotatePeriodField := "auto_rotate_period"
	if _, ok := d.GetOkExists("auto_rotate_interval"); ok {
		autoRotatePeriodField = "auto_rotate_interval"
	}

	if err := set(autoRotatePeriodField, "auto_rotate_period"); err != nil {
		return nil
	}

	return nil
}

func transitSecretBackendKeyUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Updating transit secret backend key %q", path)

	data := map[string]interface{}{
		"min_decryption_version": d.Get("min_decryption_version"),
		"min_encryption_version": d.Get("min_encryption_version"),
		"deletion_allowed":       d.Get("deletion_allowed"),
		"exportable":             d.Get("exportable"),
		"allow_plaintext_backup": d.Get("allow_plaintext_backup"),
		"auto_rotate_period":     getTransitAutoRotatePeriod(d),
	}

	_, err := client.Logical().Write(path+"/config", data)
	if err != nil {
		return fmt.Errorf("error updating transit secret backend key %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated transit secret backend key %q", path)

	return transitSecretBackendKeyRead(d, meta)
}

func transitSecretBackendKeyDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting key %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting key %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted keyu %q", path)
	return nil
}

func transitSecretBackendKeyExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if key %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if key %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if key %q exists", path)
	return secret != nil, nil
}

func transitSecretBackendKeyPath(backend string, name string) string {
	return strings.Trim(backend, "/") + "/keys/" + strings.Trim(name, "/")
}

func transitSecretBackendKeyNameFromPath(path string) (string, error) {
	if !transitSecretBackendKeyNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := transitSecretBackendKeyNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for key", len(res))
	}
	return res[1], nil
}

func transitSecretBackendKeyBackendFromPath(path string) (string, error) {
	if !transitSecretBackendKeyBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := transitSecretBackendKeyBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
