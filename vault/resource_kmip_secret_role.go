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

var kmipRoleAPIBooleanFields = []string{
	consts.FieldOperationActivate,
	consts.FieldOperationAddAttribute,
	consts.FieldOperationAll,
	consts.FieldOperationCreate,
	consts.FieldOperationCreateKeyPair,
	consts.FieldOperationDecrypt,
	consts.FieldOperationDeleteAttribute,
	consts.FieldOperationDestroy,
	consts.FieldOperationDiscoverVersions,
	consts.FieldOperationEncrypt,
	consts.FieldOperationGet,
	consts.FieldOperationGetAttributeList,
	consts.FieldOperationGetAttributes,
	consts.FieldOperationImport,
	consts.FieldOperationLocate,
	consts.FieldOperationMAC,
	consts.FieldOperationMACVerify,
	consts.FieldOperationModifyAttribute,
	consts.FieldOperationNone,
	consts.FieldOperationQuery,
	consts.FieldOperationRegister,
	consts.FieldOperationRekey,
	consts.FieldOperationRekeyKeyPair,
	consts.FieldOperationRevoke,
	consts.FieldOperationRNGRetrieve,
	consts.FieldOperationRNGSeed,
	consts.FieldOperationSign,
	consts.FieldOperationSignatureVerify,
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
			consts.FieldTLSClientKeyType: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client certificate key type, rsa or ec",
			},
			consts.FieldTLSClientKeyBits: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Client certificate key bits, valid values depend on key type",
			},
			consts.FieldTLSClientTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Client certificate TTL in seconds",
			},
			consts.FieldOperationNone: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Remove all permissions from this role. May not be specified with any other operation_* params",
			},
			consts.FieldOperationAll: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant all permissions to this role. May not be specified with any other operation_* params",
			},
			consts.FieldOperationActivate: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Activate operation",
			},
			consts.FieldOperationAddAttribute: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Add Attribute operation",
			},
			consts.FieldOperationCreate: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Create operation",
			},
			consts.FieldOperationCreateKeyPair: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Create Key Pair operation",
			},
			consts.FieldOperationDecrypt: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Decrypt operation",
			},
			consts.FieldOperationDeleteAttribute: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Delete Attribute operation",
			},
			consts.FieldOperationDestroy: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Destroy operation",
			},
			consts.FieldOperationDiscoverVersions: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Discover Version operation",
			},
			consts.FieldOperationEncrypt: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Encrypt operation",
			},
			consts.FieldOperationGet: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Get operation",
			},
			consts.FieldOperationGetAttributeList: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Get Attribute List operation",
			},
			consts.FieldOperationGetAttributes: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Get Attributes operation",
			},
			consts.FieldOperationImport: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Import operation",
			},
			consts.FieldOperationLocate: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Locate operation",
			},
			consts.FieldOperationMAC: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP MAC operation",
			},
			consts.FieldOperationMACVerify: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP MAC Verify operation",
			},
			consts.FieldOperationModifyAttribute: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Modify Attribute operation",
			},
			consts.FieldOperationQuery: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Query operation",
			},
			consts.FieldOperationRegister: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Register operation",
			},
			consts.FieldOperationRekey: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Rekey operation",
			},
			consts.FieldOperationRekeyKeyPair: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Rekey Key Pair operation",
			},
			consts.FieldOperationRevoke: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Revoke operation",
			},
			consts.FieldOperationRNGRetrieve: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP RNG Retrieve operation",
			},
			consts.FieldOperationRNGSeed: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP RNG Seed operation",
			},
			consts.FieldOperationSign: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Sign operation",
			},
			consts.FieldOperationSignatureVerify: {
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

	for _, k := range []string{consts.FieldTLSClientKeyType, consts.FieldTLSClientKeyBits, consts.FieldTLSClientTTL} {
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
	nonBooleanfields := []string{consts.FieldTLSClientKeyType, consts.FieldTLSClientKeyBits, consts.FieldTLSClientTTL}

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
