// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func azureSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: azureSecretBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(azureSecretBackendRoleRead),
		UpdateContext: azureSecretBackendRoleCreate,
		DeleteContext: azureSecretBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
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
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role to create",
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"azure_roles": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role_id": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},

						"role_name": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},

						"scope": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"azure_groups": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"object_id": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"group_name": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"application_object_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Application Object ID for an existing service principal that will be used instead of creating dynamic service principals.",
			},
			"permanently_delete": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Indicates whether the applications and service principals created by Vault will be permanently deleted when the corresponding leases expire.",
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
		},
	}
}

func azureSecretBackendRoleUpdateFields(_ context.Context, d *schema.ResourceData, meta interface{}, data map[string]interface{}) diag.Diagnostics {
	if v, ok := d.GetOk("azure_roles"); ok {
		rawAzureList := v.(*schema.Set).List()

		for _, element := range rawAzureList {
			role := element.(map[string]interface{})

			if (role["role_id"] == "") == (role["role_name"] == "") {
				return diag.Errorf("must specify at most one of 'role_name' or 'role_id'")
			}
		}

		// Vaults API requires we send the policy as an escaped string
		// So we marshall and then change into a string
		jsonAzureList, err := json.Marshal(rawAzureList)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error marshaling JSON for azure_roles %q: %s", rawAzureList, err))
		}
		jsonAzureListString := string(jsonAzureList)

		log.Printf("[DEBUG] Azure RoleSet turned to escaped JSON: %s", jsonAzureListString)
		data["azure_roles"] = jsonAzureListString
	}

	if v, ok := d.GetOk("azure_groups"); ok {
		rawAzureList := v.(*schema.Set).List()

		// Vaults API requires we send the policy as an escaped string
		// So we marshall and then change into a string
		jsonAzureList, err := json.Marshal(rawAzureList)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error marshaling JSON for azure_groups %q: %s", rawAzureList, err))
		}

		jsonAzureListString := string(jsonAzureList)

		log.Printf("[DEBUG] Azure GroupSet turned to escaped JSON: %s", jsonAzureListString)
		data["azure_groups"] = jsonAzureListString
	}

	for _, k := range []string{
		"ttl",
		"max_ttl",
		"application_object_id",
	} {
		if v, ok := d.GetOk(k); ok {
			data[k] = v.(string)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		data["permanently_delete"] = d.Get("permanently_delete").(bool)
	}

	return nil
}

func azureSecretBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

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
		return diag.FromErr(fmt.Errorf("error writing Azure Secret role %q: %s", path, err))
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
		return diag.FromErr(fmt.Errorf("error reading Azure Secret role %q: %s", path, err))
	}
	log.Printf("[DEBUG] Read Azure Secret role %q", path)

	if resp == nil {
		log.Printf("[WARN] Azure Secret role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	for _, k := range []string{
		"ttl",
		"max_ttl",
		"application_object_id",
		"permanently_delete",
	} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(fmt.Errorf("error reading %s for Azure Secret role Backend Role %q: %q", k, path, err))
			}
		}
	}

	if v, ok := resp.Data["azure_roles"]; ok {
		log.Printf("[DEBUG] Role Data from Azure: %s", v)

		err := d.Set("azure_roles", resp.Data["azure_roles"])
		if err != nil {
			return diag.FromErr(fmt.Errorf("error setting Azure roles: %s", err))
		}
	}

	if v, ok := resp.Data["azure_groups"]; ok {
		log.Printf("[DEBUG] Group Data from Azure: %s", v)

		err := d.Set("azure_groups", resp.Data["azure_groups"])
		if err != nil {
			return diag.FromErr(fmt.Errorf("error setting Azure groups: %s", err))
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
		return diag.FromErr(fmt.Errorf("Error deleting Azure Secret role %q", path))
	}
	log.Printf("[DEBUG] Deleted Azure Secret role %q", path)

	return nil
}

func azureSecretRoleResourcePath(backend, role string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(role, "/")
}
