// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldOperationActivate         = "operation_activate"
	fieldOperationAddAttribute     = "operation_add_attribute"
	fieldOperationAll              = "operation_all"
	fieldOperationCreate           = "operation_create"
	fieldOperationCreateKeyPair    = "operation_create_key_pair"
	fieldOperationDecrypt          = "operation_decrypt"
	fieldOperationDeleteAttribute  = "operation_delete_attribute"
	fieldOperationDestroy          = "operation_destroy"
	fieldOperationDiscoverVersions = "operation_discover_versions"
	fieldOperationEncrypt          = "operation_encrypt"
	fieldOperationGet              = "operation_get"
	fieldOperationGetAttributeList = "operation_get_attribute_list"
	fieldOperationGetAttributes    = "operation_get_attributes"
	fieldOperationImport           = "operation_import"
	fieldOperationLocate           = "operation_locate"
	fieldOperationMAC              = "operation_mac"
	fieldOperationMACVerify        = "operation_mac_verify"
	fieldOperationModifyAttribute  = "operation_modify_attribute"
	fieldOperationNone             = "operation_none"
	fieldOperationQuery            = "operation_query"
	fieldOperationRegister         = "operation_register"
	fieldOperationRekey            = "operation_rekey"
	fieldOperationRekeyKeyPair     = "operation_rekey_key_pair"
	fieldOperationRevoke           = "operation_revoke"
	fieldOperationRNGRetrieve      = "operation_rng_retrieve"
	fieldOperationRNGSeed          = "operation_rng_seed"
	fieldOperationSign             = "operation_sign"
	fieldOperationSignatureVerify  = "operation_signature_verify"
	fieldTLSClientKeyType          = "tls_client_key_type"
	fieldTLSClientKeyBits          = "tls_client_key_bits"
	fieldTLSClientTTL              = "tls_client_ttl"
)

var kmipRoleAPIBooleanFields = []string{
	fieldOperationActivate,
	fieldOperationAddAttribute,
	fieldOperationAll,
	fieldOperationCreate,
	fieldOperationCreateKeyPair,
	fieldOperationDecrypt,
	fieldOperationDeleteAttribute,
	fieldOperationDestroy,
	fieldOperationDiscoverVersions,
	fieldOperationEncrypt,
	fieldOperationGet,
	fieldOperationGetAttributeList,
	fieldOperationGetAttributes,
	fieldOperationImport,
	fieldOperationLocate,
	fieldOperationMAC,
	fieldOperationMACVerify,
	fieldOperationModifyAttribute,
	fieldOperationNone,
	fieldOperationQuery,
	fieldOperationRegister,
	fieldOperationRekey,
	fieldOperationRekeyKeyPair,
	fieldOperationRevoke,
	fieldOperationRNGRetrieve,
	fieldOperationRNGSeed,
	fieldOperationSign,
	fieldOperationSignatureVerify,
}

func kmipSecretRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: kmipSecretRoleCreate,
		Read:   provider.ReadWrapper(kmipSecretRoleRead),
		Update: kmipSecretRoleUpdate,
		Delete: kmipSecretRoleDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where KMIP backend is mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			consts.FieldScope: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the scope",
			},
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role",
			},
			fieldTLSClientKeyType: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client certificate key type, rsa or ec",
			},
			fieldTLSClientKeyBits: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Client certificate key bits, valid values depend on key type",
			},
			fieldTLSClientTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Client certificate TTL in seconds",
			},
			fieldOperationNone: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Remove all permissions from this role. May not be specified with any other operation_* params",
			},
			fieldOperationAll: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant all permissions to this role. May not be specified with any other operation_* params",
			},
			fieldOperationActivate: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Activate operation",
			},
			fieldOperationAddAttribute: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Add Attribute operation",
			},
			fieldOperationCreate: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Create operation",
			},
			fieldOperationCreateKeyPair: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Create Key Pair operation",
			},
			fieldOperationDecrypt: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Decrypt operation",
			},
			fieldOperationDeleteAttribute: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Delete Attribute operation",
			},
			fieldOperationDestroy: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Destroy operation",
			},
			fieldOperationDiscoverVersions: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Discover Version operation",
			},
			fieldOperationEncrypt: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Encrypt operation",
			},
			fieldOperationGet: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Get operation",
			},
			fieldOperationGetAttributeList: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Get Attribute List operation",
			},
			fieldOperationGetAttributes: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Get Attributes operation",
			},
			fieldOperationImport: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Import operation",
			},
			fieldOperationLocate: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Locate operation",
			},
			fieldOperationMAC: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP MAC operation",
			},
			fieldOperationMACVerify: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP MAC Verify operation",
			},
			fieldOperationModifyAttribute: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Modify Attribute operation",
			},
			fieldOperationQuery: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Query operation",
			},
			fieldOperationRegister: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Register operation",
			},
			fieldOperationRekey: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Rekey operation",
			},
			fieldOperationRekeyKeyPair: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Rekey Key Pair operation",
			},
			fieldOperationRevoke: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Revoke operation",
			},
			fieldOperationRNGRetrieve: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP RNG Retrieve operation",
			},
			fieldOperationRNGSeed: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP RNG Seed operation",
			},
			fieldOperationSign: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Sign operation",
			},
			fieldOperationSignatureVerify: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Signature Verify operation",
			},
		},
	}
}

func kmipSecretRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	scope := d.Get(consts.FieldScope).(string)
	role := d.Get(consts.FieldRole).(string)

	data := kmipSecretRoleRequestData(d)
	rolePath := getKMIPRolePath(d)

	log.Printf("[DEBUG] Updating %q", rolePath)
	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return fmt.Errorf("error updating KMIP role %q, err=%w", rolePath, err)
	}

	d.SetId(rolePath)

	if err := d.Set(consts.FieldScope, scope); err != nil {
		return err
	}

	if err := d.Set(consts.FieldRole, role); err != nil {
		return err
	}

	return kmipSecretRoleRead(d, meta)
}

func kmipSecretRoleRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	rolePath := d.Id()
	if rolePath == "" {
		return fmt.Errorf("expected a path as ID, got empty string")
	}

	log.Printf("[DEBUG] Reading KMIP role at %q", rolePath)
	resp, err := client.Logical().Read(rolePath)
	if err != nil {
		return fmt.Errorf("error reading KMIP role at %s, err=%w", rolePath, err)
	}
	if resp == nil {
		log.Printf("[WARN] KMIP role not found, removing from state")
		d.SetId("")

		return fmt.Errorf("expected role at %s, no role found", rolePath)
	}

	for _, k := range []string{fieldTLSClientKeyType, fieldTLSClientKeyBits, fieldTLSClientTTL} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return err
		}
	}

	for _, k := range kmipRoleAPIBooleanFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on KMIP role, err=%w", k, err)
		}
	}

	return nil
}

func kmipSecretRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	rolePath := d.Id()

	if d.HasChange(consts.FieldPath) {
		newRolePath := getKMIPRolePath(d)

		log.Printf("[DEBUG] Confirming KMIP role exists at %s", newRolePath)
		resp, err := client.Logical().Read(newRolePath)
		if err != nil {
			return fmt.Errorf("error reading role at path %s, err=%w", newRolePath, err)
		}

		if resp == nil {
			return fmt.Errorf("error remounting KMIP role to new backend path %s, err=%w", newRolePath, err)
		}
		d.SetId(newRolePath)
		rolePath = newRolePath
	}

	data := kmipSecretRoleRequestData(d)
	log.Printf("[DEBUG] Updating %q", rolePath)

	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return fmt.Errorf("error updating KMIP role %q,  err=%w", rolePath, err)
	}
	log.Printf("[DEBUG] Updated %q", rolePath)

	return kmipSecretRoleRead(d, meta)
}

func kmipSecretRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	rolePath := d.Id()

	log.Printf("[DEBUG] Deleting KMIP role %s", rolePath)
	_, err := client.Logical().Delete(rolePath)
	if err != nil {
		return fmt.Errorf("error deleting role %s", rolePath)
	}
	log.Printf("[DEBUG] Deleted KMIP role %q", rolePath)

	return nil
}

func kmipSecretRoleRequestData(d *schema.ResourceData) map[string]interface{} {
	nonBooleanfields := []string{fieldTLSClientKeyType, fieldTLSClientKeyBits, fieldTLSClientTTL}

	data := make(map[string]interface{})
	for _, k := range nonBooleanfields {
		if d.IsNewResource() {
			if v, ok := d.GetOk(k); ok {
				data[k] = v
			}
		} else if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	// Boolean fields must not be evaluated
	// otherwise all result in true
	for _, k := range kmipRoleAPIBooleanFields {
		if d.IsNewResource() {
			if v, ok := d.GetOkExists(k); ok {
				data[k] = v.(bool)
			}
		} else if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	return data
}

func getKMIPRolePath(d *schema.ResourceData) string {
	role := d.Get(consts.FieldRole).(string)

	return getKMIPScopePath(d) + "/role/" + role
}
