package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func azureSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: azureSecretBackendRoleCreate,
		Read:   azureSecretBackendRoleRead,
		Update: azureSecretBackendRoleCreate,
		Delete: azureSecretBackendRoleDelete,
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
				ForceNew:    true,
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
						},

						"role_name": {
							Type:     schema.TypeString,
							Required: true,
						},

						"scope": {
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

func azureSecretBackendRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}) {

	if v, ok := d.GetOk("azure_roles"); ok {
		rawAzureList := v.(*schema.Set).List()

		// Vaults API requires we send trhe policy as an escaped string
		// So we marshall and then change into a string
		jsonAzureList, _ := json.Marshal(rawAzureList)
		jsonAzureListString := string(jsonAzureList)

		log.Printf("[DEBUG] Azure RoleSet turned to escaped JSON: %s", jsonAzureListString)
		data["azure_roles"] = string(jsonAzureListString)
	}

	if v, ok := d.GetOk("application_object_id"); ok {
		data["application_object_id"] = v.(string)
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

}

func azureSecretBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := azureSecretRoleResourcePath(backend, role)

	data := map[string]interface{}{}
	azureSecretBackendRoleUpdateFields(d, data)

	log.Printf("[DEBUG] Writing role %q to Azure Secret backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing Azure Secret role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote role %q to Azure Secret backend", path)

	return azureSecretBackendRoleRead(d, meta)
}

func azureSecretBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}
	azureSecretBackendRoleUpdateFields(d, data)

	log.Printf("[DEBUG] Updating role %q in Azure Secret backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating Azure Secret role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated role %q to Azure Secret backend", path)

	return azureSecretBackendRoleRead(d, meta)
}

func azureSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading Azure Secret role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading Azure Secret role %q: %s", path, err)
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
	} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for Azure Secret role Backend Role %q: %q", k, path, err)
			}
		}
	}

	if v, ok := resp.Data["azure_roles"]; ok {
		log.Printf("[DEBUG] Role Data from Azure: %s", v)

		d.Set("azure_roles", resp.Data["azure_roles"])
	}

	return nil
}

func azureSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting Azure Secret role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting Azure Secret role %q", path)
	}
	log.Printf("[DEBUG] Deleted Azure Secret role %q", path)

	return nil
}

func azureSecretRoleResourcePath(backend, role string) string {
	return strings.Trim(backend, "/") + "/roles/" + strings.Trim(role, "/")
}
