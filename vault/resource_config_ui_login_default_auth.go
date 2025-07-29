// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func configUILoginDefaultAuthResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(configUILoginDefaultAuthCreateUpdate, provider.VaultVersion119),
		ReadContext:   configUILoginDefaultAuthRead,
		UpdateContext: configUILoginDefaultAuthCreateUpdate,
		DeleteContext: configUILoginDefaultAuthDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the configuration",
				ForceNew:    true,
			},
			consts.FieldNamespacePath: {
				Type:                  schema.TypeString,
				Required:              true,
				Description:           "Namespace to apply the configuration to",
				DiffSuppressFunc:      suppressDiffOnSlash,
				DiffSuppressOnRefresh: true,
				ForceNew:              true,
			},
			consts.FieldDefaultAuthType: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Default auth type",
				AtLeastOneOf: []string{consts.FieldBackupAuthTypes},
			},
			consts.FieldBackupAuthTypes: {
				Type:         schema.TypeSet,
				Description:  "Backup auth types",
				Optional:     true,
				AtLeastOneOf: []string{consts.FieldDefaultAuthType},
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldDisableInheritance: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Disallow child namespaces from inheriting this configuration",
			},
		},
	}
}

func configUILoginDefaultAuthCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if !provider.IsEnterpriseSupported(meta) {
		return diag.Errorf("config_ui_login_default_auth is not supported by this version of vault")
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	data := map[string]interface{}{}

	// Parse Data
	name := d.Get(consts.FieldName).(string)

	data[consts.FieldNamespacePath] = d.Get(consts.FieldNamespacePath).(string)

	data[consts.FieldDefaultAuthType] = d.Get(consts.FieldDefaultAuthType).(string)
	if v, ok := d.GetOk(consts.FieldBackupAuthTypes); ok && v != nil {
		data[consts.FieldBackupAuthTypes] = util.TerraformSetToStringArray(v)
	}
	if v, ok := d.GetOk(consts.FieldDisableInheritance); ok {
		data[consts.FieldDisableInheritance] = v.(bool)
	}

	// Need to extract name from data passed in
	_, e = client.Logical().WriteWithContext(ctx, "sys/config/ui/login/default-auth/"+name, data)
	if e != nil {
		return diag.FromErr(e)
	}

	if d.IsNewResource() {
		d.SetId(name)
	}

	return configUILoginDefaultAuthRead(ctx, d, meta)
}

func configUILoginDefaultAuthRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	secret, e := client.Logical().ReadWithContext(ctx, "sys/config/ui/login/default-auth/"+id)
	if e != nil {
		if util.Is404(e) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(e)
	}

	if secret == nil || secret.Data == nil {
		log.Printf("[DEBUG] response from Vault server is empty for %q, removing from state", id)
		d.SetId("")
		return nil
	}

	secretData := secret.Data

	if _, ok := secretData["error"]; ok {
		errorList := secretData["error"].([]string)
		return diag.Errorf("errors received from Vault server: %s", errorList)
	}

	// Parse values
	log.Printf("[DEBUG] response from Vault server: %s", secretData)

	d.Set(consts.FieldName, id)
	d.Set(consts.FieldNamespacePath, secretData[consts.FieldNamespacePath].(string))
	d.Set(consts.FieldDefaultAuthType, secretData[consts.FieldDefaultAuthType].(string))
	d.Set(consts.FieldDisableInheritance, secretData[consts.FieldDisableInheritance].(bool))

	var backupAuthTypes []string
	if secretData[consts.FieldBackupAuthTypes] != nil {
		for _, v := range secretData[consts.FieldBackupAuthTypes].([]interface{}) {
			backupAuthTypes = append(backupAuthTypes, v.(string))
		}

	}
	d.Set(consts.FieldBackupAuthTypes, backupAuthTypes)

	return nil
}

func configUILoginDefaultAuthDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	log.Printf("[DEBUG] Deleting default login configuration %q", id)
	_, e = client.Logical().DeleteWithContext(ctx, "sys/config/ui/login/default-auth/"+id)
	if e != nil {
		return diag.Errorf("error deleting default login configuration %q: %s", id, e)
	}

	log.Printf("[DEBUG] Deleted default login configuration %q", id)
	return nil
}

func suppressDiffOnSlash(_, oldVal, NewVal string, _ *schema.ResourceData) bool {
	return mountutil.TrimSlashes(oldVal) == mountutil.TrimSlashes(NewVal)
}
