package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const (
	fieldOperationActivate         = "operation_activate"
	fieldOperationAddAttribute     = "operation_add_attribute"
	fieldOperationAll              = "operation_all"
	fieldOperationCreate           = "operation_create"
	fieldOperationDestroy          = "operation_destroy"
	fieldOperationDiscoverVersions = "operation_discover_versions"
	fieldOperationGet              = "operation_get"
	fieldOperationGetAttributeList = "operation_get_attribute_list"
	fieldOperationGetAttributes    = "operation_get_attributes"
	fieldOperationLocate           = "operation_locate"
	fieldOperationNone             = "operation_none"
	fieldOperationRegister         = "operation_register"
	fieldOperationRekey            = "operation_rekey"
	fieldOperationRevoke           = "operation_revoke"
)

var kmipRoleAPIBooleanFields = []string{
	fieldOperationActivate,
	fieldOperationAddAttribute,
	fieldOperationAll,
	fieldOperationCreate,
	fieldOperationDestroy,
	fieldOperationDiscoverVersions,
	fieldOperationGet,
	fieldOperationGetAttributeList,
	fieldOperationGetAttributes,
	fieldOperationLocate,
	fieldOperationNone,
	fieldOperationRegister,
	fieldOperationRekey,
	fieldOperationRevoke,
}

func kmipSecretRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: kmipSecretRoleCreate,
		Read:   kmipSecretRoleRead,
		Update: kmipSecretRoleUpdate,
		Delete: kmipSecretRoleDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where KMIP backend is mounted",
				ValidateFunc: validateNoTrailingLeadingSlashes,
			},
			"scope": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the scope",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role",
			},
			"tls_client_key_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client certificate key type, rsa or ec",
			},
			"tls_client_key_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Client certificate key bits, valid values depend on key type",
			},
			"tls_client_ttl": {
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
			fieldOperationLocate: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Locate operation",
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
			fieldOperationRevoke: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Grant permission to use the KMIP Revoke operation",
			},
		},
	}
}

func kmipSecretRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	scope := d.Get("scope").(string)
	role := d.Get("role").(string)

	data := map[string]interface{}{}
	if v, ok := d.GetOk("tls_client_key_bits"); ok {
		data["tls_client_key_bits"] = v.(int)
	}

	if v, ok := d.GetOk("tls_client_key_type"); ok {
		data["tls_client_key_type"] = v.(string)
	}

	if v, ok := d.GetOk("tls_client_ttl"); ok {
		data["tls_client_ttl"] = v.(int)
	}

	for _, k := range kmipRoleAPIBooleanFields {
		if v, ok := d.GetOkExists(k); ok {
			data[k] = v.(bool)
		}
	}

	rolePath := path + "/scope/" + scope + "/role/" + role
	log.Printf("[DEBUG] Updating %q", rolePath)
	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return fmt.Errorf("error updating KMIP role %q, err=%w", rolePath, err)
	}

	d.SetId(rolePath)

	if err := d.Set("scope", scope); err != nil {
		return err
	}

	if err := d.Set("role", role); err != nil {
		return err
	}

	return kmipSecretRoleRead(d, meta)
}

func kmipSecretRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
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

	for _, k := range []string{"tls_client_key_bits", "tls_client_key_type", "tls_client_ttl"} {
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
	client := meta.(*api.Client)
	rolePath := d.Id()

	if d.HasChange("path") {
		newMountPath := d.Get("path").(string)
		scope := d.Get("scope").(string)
		role := d.Get("role").(string)
		newRolePath := newMountPath + "/scope/" + scope + "/role/" + role

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

	data := map[string]interface{}{}
	log.Printf("[DEBUG] Updating %q", rolePath)

	if d.HasChange("tls_client_key_bits") {
		data["tls_client_key_bits"] = d.Get("tls_client_key_bits").(int)
	}

	if d.HasChange("tls_client_key_type") {
		data["tls_client_key_type"] = d.Get("tls_client_key_type").(string)
	}

	if d.HasChange("tls_client_ttl") {
		data["tls_client_ttl"] = d.Get("tls_client_ttl").(int)
	}

	for _, k := range kmipRoleAPIBooleanFields {
		if d.HasChange(k) {
			data[k] = d.Get(k).(bool)
		}
	}

	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return fmt.Errorf("error updating KMIP role %q,  err=%w", rolePath, err)
	}
	log.Printf("[DEBUG] Updated %q", rolePath)

	return kmipSecretRoleRead(d, meta)
}

func kmipSecretRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	rolePath := d.Id()

	log.Printf("[DEBUG] Deleting KMIP role %s", rolePath)
	_, err := client.Logical().Delete(rolePath)
	if err != nil {
		return fmt.Errorf("error deleting role %s", rolePath)
	}
	log.Printf("[DEBUG] Deleted KMIP role %q", rolePath)

	return nil
}
