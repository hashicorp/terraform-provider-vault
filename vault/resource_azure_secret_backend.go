// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func azureSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		Create: azureSecretBackendCreate,
		Read:   provider.ReadWrapper(azureSecretBackendRead),
		Update: azureSecretBackendUpdate,
		Delete: azureSecretBackendDelete,
		Exists: azureSecretBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "azure",
				Description: "Path to mount the backend at.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, fmt.Errorf("path cannot end in '/'"))
					}
					return
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"use_microsoft_graph_api": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Use the Microsoft Graph API. Should be set to true on vault-1.10+",
			},
			"subscription_id": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Required:    true,
				Sensitive:   true,
				Description: "The subscription id for the Azure Active Directory.",
			},
			"tenant_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The tenant id for the Azure Active Directory organization.",
				Sensitive:   true,
			},
			"client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The client id for credentials to query the Azure APIs. Currently read permissions to query compute resources are required.",
				Sensitive:   true,
			},
			"client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The client secret for credentials to query the Azure APIs",
				Sensitive:   true,
			},
			"environment": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "AzurePublicCloud",
				Description: "The Azure cloud environment. Valid values: AzurePublicCloud, AzureUSGovernmentCloud, AzureChinaCloud, AzureGermanCloud.",
			},
		},
	}, false)
}

func azureSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get("path").(string)
	description := d.Get("description").(string)
	configPath := azureSecretBackendPath(path)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Azure backend at %q", path)
	input := &api.MountInput{
		Type:        "azure",
		Description: description,
		Config:      api.MountConfigInput{},
	}
	if err := client.Sys().Mount(path, input); err != nil {
		return fmt.Errorf("error mounting to %q: %s", path, err)
	}

	log.Printf("[DEBUG] Mounted Azure backend at %q", path)
	d.SetId(path)

	log.Printf("[DEBUG] Writing Azure configuration to %q", configPath)
	data := azureSecretBackendRequestData(d, meta)
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("error writing Azure configuration for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Azure configuration to %q", configPath)
	d.Partial(false)

	return azureSecretBackendRead(d, meta)
}

func azureSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading Azure backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Azure backend mount %q from Vault", path)

	// the API always returns the path with a trailing slash, so let's make
	// sure we always specify it as a trailing slash.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing backend from state.", path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Read Azure secret Backend config %s", path)
	resp, err := client.Logical().Read(azureSecretBackendPath(path))
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	for _, k := range []string{"client_id", "subscription_id", "tenant_id"} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return err
			}
		}
	}

	skipMSGraphAPI := provider.IsAPISupported(meta, provider.VaultVersion112)

	if !skipMSGraphAPI {
		if v, ok := resp.Data["use_microsoft_graph_api"]; ok {
			if err := d.Set("use_microsoft_graph_api", v); err != nil {
				return err
			}
		}
	}

	if v, ok := resp.Data["environment"]; ok && v.(string) != "" {
		if err := d.Set("environment", v); err != nil {
			return err
		}
	} else {
		if err := d.Set("environment", "AzurePublicCloud"); err != nil {
			return err
		}
	}

	if err := d.Set("path", path); err != nil {
		return err
	}

	if err := d.Set("description", mount.Description); err != nil {
		return err
	}

	return nil
}

func azureSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	path, err := util.Remount(d, client, consts.FieldPath, false)
	if err != nil {
		return err
	}

	data := azureSecretBackendRequestData(d, meta)
	if len(data) > 0 {
		_, err := client.Logical().Write(azureSecretBackendPath(path), data)
		if err != nil {
			return fmt.Errorf("error writing config for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated Azure Backend Config at %q", azureSecretBackendPath(path))
	}

	return azureSecretBackendRead(d, meta)
}

func azureSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Azure backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error unmounting Azure backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Azure backend %q", path)
	return nil
}

func azureSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if Azure backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if Azure backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}

func azureSecretBackendPath(path string) string {
	return strings.Trim(path, "/") + "/config"
}

func azureSecretBackendRequestData(d *schema.ResourceData, meta interface{}) map[string]interface{} {
	fields := []string{
		"client_id",
		"environment",
		"tenant_id",
		"client_secret",
		"subscription_id",
	}

	skipMSGraphAPI := provider.IsAPISupported(meta, provider.VaultVersion112)

	if _, ok := d.GetOk("use_microsoft_graph_api"); ok {
		if skipMSGraphAPI {
			log.Printf("ignoring this field because Vault version is greater than 1.12")
		}
	}

	if !skipMSGraphAPI {
		fields = append(fields, "use_microsoft_graph_api")
	}

	data := make(map[string]interface{})
	for _, k := range fields {
		if d.IsNewResource() {
			data[k] = d.Get(k)
		} else if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	return data
}
