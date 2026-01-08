// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/util"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var azureSecretFields = []string{
	consts.FieldExplicitMaxTTL,
	consts.FieldMaxTTL,
	consts.FieldTTL,
	consts.FieldApplicationObjectID,
}

func azureSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: azureSecretBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(azureSecretBackendRoleRead),
		UpdateContext: azureSecretBackendRoleCreate,
		DeleteContext: azureSecretBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "azure",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role to create",
				ForceNew:    true,
			},
			consts.FieldDescription: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			consts.FieldAzureRoles: {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						consts.FieldRoleID: {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},

						consts.FieldRoleName: {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},

						consts.FieldScope: {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			consts.FieldAzureGroups: {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						consts.FieldObjectID: {
							Type:     schema.TypeString,
							Computed: true,
						},

						consts.FieldGroupName: {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			consts.FieldApplicationObjectID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Application Object ID for an existing service principal that will be used instead of creating dynamic service principals.",
			},
			consts.FieldPermanentlyDelete: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Indicates whether the applications and service principals created by Vault will be permanently deleted when the corresponding leases expire.",
			},
			consts.FieldTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the default TTL for service principals generated using this role.",
			},
			consts.FieldMaxTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "0",
				Description: "Specifies the maximum TTL for service principals generated using this role.",
			},
			consts.FieldExplicitMaxTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "0",
				Description: "Specifies the explicit maximum lifetime of the lease and service principal.",
			},
			consts.FieldSignInAudience: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the security principal types that are allowed to sign in to the application. Valid values are: AzureADMyOrg, AzureADMultipleOrgs, AzureADandPersonalMicrosoftAccount, PersonalMicrosoftAccount",
			},
			consts.FieldTags: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:    true,
				Description: "Comma-separated strings of Azure tags to attach to an application.",
			},
			consts.FieldPersistApp: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If true, persists the created service principal and application for the lifetime of the role.",
			},
			consts.FieldMetadata: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "A map of string key/value pairs that will be stored as metadata on the secret.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func azureSecretBackendRoleUpdateFields(_ context.Context, d *schema.ResourceData, meta interface{}, data map[string]interface{}) diag.Diagnostics {
	if v, ok := d.GetOk(consts.FieldAzureRoles); ok {
		rawAzureList := v.(*schema.Set).List()

		for _, element := range rawAzureList {
			role := element.(map[string]interface{})

			if (role[consts.FieldRoleID] == "") && (role[consts.FieldRoleName] == "") {
				return diag.Errorf("must specify one of 'role_name' or 'role_id'")
			}
		}

		// Vaults API requires we send the policy as an escaped string
		// So we marshall and then change into a string
		jsonAzureList, err := json.Marshal(rawAzureList)
		if err != nil {
			return diag.Errorf("error marshaling JSON for azure_roles %q: %s", rawAzureList, err)
		}
		jsonAzureListString := string(jsonAzureList)

		log.Printf("[DEBUG] Azure RoleSet turned to escaped JSON: %s", jsonAzureListString)
		data[consts.FieldAzureRoles] = jsonAzureListString
	}

	if v, ok := d.GetOk(consts.FieldAzureGroups); ok {
		rawAzureList := v.(*schema.Set).List()

		// Vaults API requires we send the policy as an escaped string
		// So we marshall and then change into a string
		jsonAzureList, err := json.Marshal(rawAzureList)
		if err != nil {
			return diag.Errorf("error marshaling JSON for azure_groups %q: %s", rawAzureList, err)
		}

		jsonAzureListString := string(jsonAzureList)

		log.Printf("[DEBUG] Azure GroupSet turned to escaped JSON: %s", jsonAzureListString)
		data[consts.FieldAzureGroups] = jsonAzureListString
	}

	for _, k := range azureSecretFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v.(string)
		}
	}

	useAPIVer121Ent := provider.IsAPISupported(meta, provider.VaultVersion121) && provider.IsEnterpriseSupported(meta)
	if useAPIVer121Ent {
		if d.IsNewResource() {
			if v, ok := d.GetOk(consts.FieldMetadata); ok && len(v.(map[string]interface{})) > 0 {
				data[consts.FieldMetadata] = v.(map[string]interface{})
			}
		} else if d.HasChange(consts.FieldMetadata) {
			data[consts.FieldMetadata] = d.Get(consts.FieldMetadata)
		}
	} else {
		if v, ok := d.GetOk(consts.FieldMetadata); ok && len(v.(map[string]interface{})) > 0 {
			return diag.Errorf("%q is only supported on Vault Enterprise %s or newer",
				consts.FieldMetadata, provider.VaultVersion121)
		}
	}

	useAPIVer118 := provider.IsAPISupported(meta, provider.VaultVersion118)
	if useAPIVer118 {
		if v, ok := d.GetOk(consts.FieldExplicitMaxTTL); ok && v != "" {
			data[consts.FieldExplicitMaxTTL] = v
		}
	}

	useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116)
	if useAPIVer116 {
		if v, ok := d.GetOk(consts.FieldSignInAudience); ok && v != "" {
			data[consts.FieldSignInAudience] = v
		}
		// handle comma separated string field
		if v, ok := d.GetOk(consts.FieldTags); ok {
			tags := util.ToStringArray(v.([]interface{}))
			if len(tags) > 0 {
				data[consts.FieldTags] = strings.Join(tags, ",")
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		data[consts.FieldPermanentlyDelete] = d.Get(consts.FieldPermanentlyDelete).(bool)
	}

	data[consts.FieldPersistApp] = d.Get(consts.FieldPersistApp).(bool)

	return nil
}

func azureSecretBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	role := d.Get(consts.FieldRole).(string)

	path := azureSecretRoleResourcePath(backend, role)

	data := map[string]interface{}{}
	if diags := azureSecretBackendRoleUpdateFields(ctx, d, meta, data); diags != nil {
		return diags
	}

	log.Printf("[DEBUG] Writing role %q to Azure Secret backend", path)
	d.SetId(path)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("error writing Azure Secret role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote role %q to Azure Secret backend", path)

	return azureSecretBackendRoleRead(ctx, d, meta)
}

func azureSecretBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading Azure Secret role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading Azure Secret role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Azure Secret role %q", path)

	if resp == nil {
		log.Printf("[WARN] Azure Secret role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	for _, k := range azureSecretFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for Azure Secret role Backend Role %q: %q", k, path, err)
			}
		}
	}

	if v, ok := resp.Data[consts.FieldPermanentlyDelete]; ok {
		if err := d.Set(consts.FieldPermanentlyDelete, v); err != nil {
			return diag.Errorf("error setting permanently delete field: %s", err)
		}
	}

	useAPIVer121Ent := provider.IsAPISupported(meta, provider.VaultVersion121) && provider.IsEnterpriseSupported(meta)
	if useAPIVer121Ent {
		if err := d.Set(consts.FieldMetadata, resp.Data[consts.FieldMetadata]); err != nil {
			return diag.FromErr(err)
		}
	}

	useAPIVer118 := provider.IsAPISupported(meta, provider.VaultVersion118)
	if useAPIVer118 {
		if err := d.Set(consts.FieldExplicitMaxTTL, resp.Data[consts.FieldExplicitMaxTTL]); err != nil {
			return diag.FromErr(err)
		}
	}

	useAPIVer116 := provider.IsAPISupported(meta, provider.VaultVersion116)
	if useAPIVer116 {
		if err := d.Set(consts.FieldSignInAudience, resp.Data[consts.FieldSignInAudience]); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set(consts.FieldTags, resp.Data[consts.FieldTags]); err != nil {
			return diag.FromErr(err)
		}
	}

	if v, ok := resp.Data[consts.FieldAzureRoles]; ok {
		log.Printf("[DEBUG] Role Data from Azure: %s", v)

		err := d.Set(consts.FieldAzureRoles, resp.Data[consts.FieldAzureRoles])
		if err != nil {
			return diag.Errorf("error setting Azure roles: %s", err)
		}
	}

	if v, ok := resp.Data[consts.FieldAzureGroups]; ok {
		log.Printf("[DEBUG] Group Data from Azure: %s", v)

		err := d.Set(consts.FieldAzureGroups, resp.Data[consts.FieldAzureGroups])
		if err != nil {
			return diag.Errorf("error setting Azure groups: %s", err)
		}
	}

	if v, ok := resp.Data[consts.FieldPersistApp]; ok {
		log.Printf("[DEBUG] Persist App from Azure: %s", v)
		if err := d.Set(consts.FieldPersistApp, v); err != nil {
			return diag.Errorf("error setting persist_app field: %s", err)
		}
	}

	return nil
}

func azureSecretBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting Azure Secret role %q", path)
	_, err = client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("Error deleting Azure Secret role %q", path)
	}
	log.Printf("[DEBUG] Deleted Azure Secret role %q", path)

	return nil
}

func azureSecretRoleResourcePath(backend, role string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(role, "/")
}
