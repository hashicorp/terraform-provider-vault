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
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
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
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the resource belongs to.",
				ForceNew:    true,
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the encryption key to create.",
				ForceNew:    true,
			},
			consts.FieldDeletionAllowed: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies if the key is allowed to be deleted.",
				Default:     false,
			},
			consts.FieldConvergentEncryption: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether or not to support convergent encryption, where the same plaintext creates the same ciphertext. This requires derived to be set to true.",
				ForceNew:    true,
				Default:     false,
			},
			consts.FieldDerived: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies if key derivation is to be used. If enabled, all encrypt/decrypt requests to this key must provide a context which is used for key derivation.",
				ForceNew:    true,
				Default:     false,
			},
			consts.FieldExportable: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enables keys to be exportable. This allows for all the valid keys in the key ring to be exported. Once set, this cannot be disabled.",
				Default:     false,
			},
			consts.FieldAllowPlaintextBackup: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, enables taking backup of named key in the plaintext format. Once set, this cannot be disabled.",
				Default:     false,
			},
			consts.FieldAutoRotatePeriod: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Amount of seconds the key should live before being automatically rotated. A value of 0 disables automatic rotation for the key.",
			},
			consts.FieldType: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the type of key to create. The currently-supported types are: `aes128-gcm96`, `aes256-gcm96` (default), `chacha20-poly1305`, `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `hmac`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `managed_key`, `aes128-cmac`, `aes192-cmac`, `aes256-cmac`, `ml-dsa`, `hybrid`, and `slh-dsa`.",
				ForceNew:    true,
				Default:     "aes256-gcm96",
			},
			consts.FieldKeys: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of key versions in the keyring.",
				Elem: &schema.Schema{
					Type: schema.TypeMap,
					Elem: schema.TypeString,
				},
			},
			consts.FieldKeySize: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The key size in bytes for algorithms that allow variable key sizes. Currently only applicable to HMAC; this value must be between 32 and 512.",
				Default:     0,
			},
			consts.FieldLatestVersion: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Latest key version in use in the keyring",
			},
			consts.FieldMinAvailableVersion: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Minimum key version available for use.",
			},
			consts.FieldMinDecryptionVersion: {
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
			consts.FieldMinEncryptionVersion: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Minimum key version to use for encryption",
				Default:     0,
			},
			consts.FieldParameterSet: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The parameter set to use for ML-DSA. Required for ML-DSA and hybrid keys.  Valid values for ML-DSA are `44`, `65`, and `87`. Valid values for SLH-DSA are `slh-dsa-sha2-128s`, `slh-dsa-shake-128s`, `slh-dsa-sha2-128f`, `slh-dsa-shake-128`, `slh-dsa-sha2-192s`, `slh-dsa-shake-192s`, `slh-dsa-sha2-192f`, `slh-dsa-shake-192f`, `slh-dsa-sha2-256s`, `slh-dsa-shake-256s`, `slh-dsa-sha2-256f`, and `slh-dsa-shake-256f`.",
			},
			consts.FieldHybridKeyTypeEC: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The elliptic curve algorithm to use for hybrid signatures. Supported key types are `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, and `ed25519`.",
			},
			consts.FieldHybridKeyTypePQC: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The post-quantum algorithm to use for hybrid signatures. Currently, ML-DSA is the only supported key type.",
			},
			consts.FieldContext: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Base64 encoded context for key derivation. Required if derived is set to true.",
			},
			consts.FieldManagedKeyName: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The name of the managed key to use when the key type is managed_key.",
			},
			consts.FieldManagedKeyID: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The UUID of the managed key to use when the key type is managed_key.",
			},
			consts.FieldSupportsEncryption: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports encryption, based on key type.",
			},
			consts.FieldSupportsDecryption: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports decryption, based on key type.",
			},
			consts.FieldSupportsDerivation: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports derivation, based on key type.",
			},
			consts.FieldSupportsSigning: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether or not the key supports signing, based on key type.",
			},
		},
		CustomizeDiff: customdiff.All(
			customdiff.ValidateChange(consts.FieldExportable, func(_ context.Context, old, new, meta interface{}) error {
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
			customdiff.ValidateChange(consts.FieldAllowPlaintextBackup, func(_ context.Context, old, new, meta interface{}) error {
				// Same conditions as above. This cannot be disabled once enabled.
				if new.(bool) && !old.(bool) {
					return nil
				}
				if !new.(bool) && old.(bool) {
					return fmt.Errorf("'allow_plaintext_backup' cannot be disabled on a key that already has it enabled")
				}
				return nil
			}),
			customdiff.ForceNewIfChange(consts.FieldExportable, func(_ context.Context, old, new, meta interface{}) bool {
				return !new.(bool) && old.(bool)
			}),
			customdiff.ForceNewIfChange(consts.FieldAllowPlaintextBackup, func(_ context.Context, old, new, meta interface{}) bool {
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

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get(consts.FieldName).(string)

	path := transitSecretBackendKeyPath(backend, name)

	autoRotatePeriod := getTransitAutoRotatePeriod(d)
	configData := map[string]interface{}{
		"min_decryption_version": d.Get(consts.FieldMinDecryptionVersion).(int),
		"min_encryption_versoin": d.Get(consts.FieldMinEncryptionVersion).(int),
		"deletion_allowed":       d.Get(consts.FieldDeletionAllowed).(bool),
		"exportable":             d.Get(consts.FieldExportable).(bool),
		"allow_plaintext_backup": d.Get(consts.FieldAllowPlaintextBackup).(bool),
		"auto_rotate_period":     autoRotatePeriod,
	}

	data := map[string]interface{}{
		"convergent_encryption": d.Get(consts.FieldConvergentEncryption).(bool),
		"derived":               d.Get(consts.FieldDerived).(bool),
		"type":                  d.Get(consts.FieldType).(string),
		"auto_rotate_period":    autoRotatePeriod,
	}

	if context, ok := d.GetOk(consts.FieldContext); ok {
		data[consts.FieldContext] = context
	}

	if provider.IsAPISupported(meta, provider.VaultVersion113) {
		if managedKeyName, ok := d.GetOk(consts.FieldManagedKeyName); ok {
			data[consts.FieldManagedKeyName] = managedKeyName
		}

		if managedKeyID, ok := d.GetOk(consts.FieldManagedKeyID); ok {
			data[consts.FieldManagedKeyID] = managedKeyID
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion119) {
		if params, ok := d.GetOk(consts.FieldParameterSet); ok {
			data[consts.FieldParameterSet] = params
		}

		if params, ok := d.GetOk(consts.FieldHybridKeyTypeEC); ok {
			data[consts.FieldHybridKeyTypeEC] = params
		}

		if params, ok := d.GetOk(consts.FieldHybridKeyTypePQC); ok {
			data[consts.FieldHybridKeyTypePQC] = params
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		data[consts.FieldKeySize] = d.Get(consts.FieldKeySize).(int)
	}

	log.Printf("[DEBUG] Creating encryption key %s on transit secret backend %q", name, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating encryption key %s for transit secret backend %q: %s with key size %d", name, backend, err, d.Get(consts.FieldKeySize).(int))
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
	v, ok := d.GetOkExists(consts.FieldAutoRotatePeriod)
	if ok {
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
	iConvergentEncryption := secret.Data[consts.FieldConvergentEncryption]
	convergentEncryption := false
	if ce, ok := iConvergentEncryption.(bool); ok {
		convergentEncryption = ce
	}

	latestVersion, err := secret.Data[consts.FieldLatestVersion].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected latest_version %q to be a number, and it isn't", secret.Data[consts.FieldLatestVersion])
	}

	minAvailableVersion, err := secret.Data[consts.FieldMinAvailableVersion].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected min_available_version %q to be a number, and it isn't", secret.Data[consts.FieldMinAvailableVersion])
	}

	minDecryptionVersion, err := secret.Data[consts.FieldMinDecryptionVersion].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected min_decryption_version %q to be a number, and it isn't", secret.Data[consts.FieldMinDecryptionVersion])
	}

	minEncryptionVersion, err := secret.Data[consts.FieldMinEncryptionVersion].(json.Number).Int64()
	if err != nil {
		return fmt.Errorf("expected min_encryption_version %q to be a number, and it isn't", secret.Data[consts.FieldMinEncryptionVersion])
	}

	ikeys := secret.Data[consts.FieldKeys]
	keys := []interface{}{}
	if ikeys != nil {
		ikeys := secret.Data[consts.FieldKeys].(map[string]interface{})
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

	if err := d.Set(consts.FieldKeys, keys); err != nil {
		return err
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		// On read, key_size will be nil if the encryption key type is not HMAC. Choosing not to set it in those cases.
		keySize := secret.Data[consts.FieldKeySize]
		if keySize != nil || secret.Data[consts.FieldType] == "hmac" {
			keySize, err := secret.Data[consts.FieldKeySize].(json.Number).Int64()
			if err != nil {
				return fmt.Errorf("expected key_size %q to be a number, and it isn't", secret.Data[consts.FieldKeySize])
			}
			if err := d.Set(consts.FieldKeySize, keySize); err != nil {
				return err
			}
		}
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return err
	}
	if err := d.Set(consts.FieldName, name); err != nil {
		return err
	}
	if err := d.Set(consts.FieldLatestVersion, latestVersion); err != nil {
		return err
	}
	if err := d.Set(consts.FieldMinAvailableVersion, minAvailableVersion); err != nil {
		return err
	}
	if err := d.Set(consts.FieldMinDecryptionVersion, minDecryptionVersion); err != nil {
		return err
	}
	if err := d.Set(consts.FieldMinEncryptionVersion, minEncryptionVersion); err != nil {
		return err
	}
	if err := d.Set(consts.FieldConvergentEncryption, convergentEncryption); err != nil {
		return err
	}

	fields := []string{
		consts.FieldAllowPlaintextBackup,
		consts.FieldDeletionAllowed, consts.FieldDerived, consts.FieldExportable,
		consts.FieldSupportsDecryption, consts.FieldSupportsDerivation,
		consts.FieldSupportsEncryption, consts.FieldSupportsSigning, consts.FieldType,
		consts.FieldAutoRotatePeriod, consts.FieldContext,
	}

	for _, f := range fields {
		if v, ok := secret.Data[f]; ok {
			if err := d.Set(f, v); err != nil {
				return err
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion113) {
		managedKeyFields := []string{consts.FieldManagedKeyName, consts.FieldManagedKeyID}
		for _, f := range managedKeyFields {
			if v, ok := secret.Data[f]; ok {
				if err := d.Set(f, v); err != nil {
					return err
				}
			}
		}
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
		"min_decryption_version": d.Get(consts.FieldMinDecryptionVersion),
		"min_encryption_version": d.Get(consts.FieldMinEncryptionVersion),
		"deletion_allowed":       d.Get(consts.FieldDeletionAllowed),
		"exportable":             d.Get(consts.FieldExportable),
		"allow_plaintext_backup": d.Get(consts.FieldAllowPlaintextBackup),
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
