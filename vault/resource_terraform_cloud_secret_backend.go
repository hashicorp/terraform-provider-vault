// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-cty/cty"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func terraformCloudSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		Create:        terraformCloudSecretBackendCreate,
		Read:          provider.ReadWrapper(terraformCloudSecretBackendRead),
		Update:        terraformCloudSecretBackendUpdate,
		Delete:        terraformCloudSecretBackendDelete,
		Exists:        terraformCloudSecretBackendExists,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldBackend),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     consts.MountTypeTerraform,
				Description: "Unique name of the Vault Terraform Cloud mount to configure",
				StateFunc: func(s interface{}) string {
					return strings.Trim(s.(string), "/")
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			consts.FieldToken: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "Specifies the Terraform Cloud access token to use.",
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldTokenWO},
			},
			consts.FieldTokenWO: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "Write-only Terraform Cloud access token to use.",
				Sensitive:     true,
				WriteOnly:     true,
				ConflictsWith: []string{consts.FieldToken},
			},
			consts.FieldTokenWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Version counter for write-only secret data.",
				RequiredWith: []string{consts.FieldTokenWO},
			},
			consts.FieldAddress: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "https://app.terraform.io",
				Description: "Specifies the address of the Terraform Cloud instance, provided as \"host:port\" like \"127.0.0.1:8500\".",
			},
			consts.FieldBasePath: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "/api/v2/",
				Description: "Specifies the base path for the Terraform Cloud or Enterprise API.",
			},
			consts.FieldDescription: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			consts.FieldDefaultLeaseTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
				Description: "Default lease duration for secrets in seconds",
			},
			consts.FieldMaxLeaseTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
				Description: "Maximum possible lease duration for secrets in seconds",
			},
		},
	}, false)
}

func terraformCloudSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get(consts.FieldBackend).(string)
	address := d.Get(consts.FieldAddress).(string)
	basePath := d.Get(consts.FieldBasePath).(string)
	description := d.Get(consts.FieldDescription).(string)
	defaultLeaseTTL := d.Get(consts.FieldDefaultLeaseTTL)
	maxLeaseTTL := d.Get(consts.FieldMaxLeaseTTL)

	configPath := terraformCloudSecretBackendConfigPath(backend)

	info := &api.MountInput{
		Type:        consts.MountTypeTerraform,
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultLeaseTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxLeaseTTL),
		},
	}

	log.Printf("[DEBUG] Mounting Terraform Cloud backend at %q", backend)

	if err := client.Sys().Mount(backend, info); err != nil {
		return fmt.Errorf("Error mounting to %q: %s", backend, err)
	}

	log.Printf("[DEBUG] Mounted Terraform Cloud backend at %q", backend)
	d.SetId(backend)

	d.Set(consts.FieldBackend, backend)
	d.Set(consts.FieldDescription, description)
	d.Set(consts.FieldDefaultLeaseTTL, defaultLeaseTTL)
	d.Set(consts.FieldMaxLeaseTTL, maxLeaseTTL)

	log.Printf("[DEBUG] Writing Terraform Cloud configuration to %q", configPath)
	data := map[string]interface{}{
		consts.FieldAddress:  address,
		consts.FieldBasePath: basePath,
	}
	var token string
	if v, ok := d.GetOk(consts.FieldToken); ok {
		token = v.(string)
		d.Set(consts.FieldToken, token)
	} else if d.IsNewResource() || d.HasChange(consts.FieldTokenWOVersion) {
		p := cty.GetAttrPath(consts.FieldTokenWO)
		woVal, _ := d.GetRawConfigAt(p)
		token = woVal.AsString()
	}

	if token != "" {
		data[consts.FieldToken] = token
	}

	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("Error writing Terraform Cloud configuration for %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Wrote Terraform Cloud configuration to %q", configPath)
	d.Set(consts.FieldAddress, address)
	d.Set(consts.FieldBasePath, basePath)

	return nil
}

func terraformCloudSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Id()
	configPath := terraformCloudSecretBackendConfigPath(backend)

	log.Printf("[DEBUG] Reading Terraform Cloud backend mount %q from Vault", backend)

	ctx := context.Background()
	mount, err := mountutil.GetMount(ctx, client, backend)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", backend)
			d.SetId("")
			return nil
		}
		return err
	}

	d.Set(consts.FieldBackend, backend)
	d.Set(consts.FieldDescription, mount.Description)
	d.Set(consts.FieldDefaultLeaseTTL, mount.Config.DefaultLeaseTTL)
	d.Set(consts.FieldMaxLeaseTTL, mount.Config.MaxLeaseTTL)

	log.Printf("[DEBUG] Reading %s from Vault", configPath)
	secret, err := client.Logical().Read(configPath)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	// token, sadly, we can't read out
	// the API doesn't support it
	// So... if it drifts, it drift.
	d.Set(consts.FieldAddress, secret.Data[consts.FieldAddress].(string))
	d.Set(consts.FieldBasePath, secret.Data[consts.FieldBasePath].(string))

	return nil
}

func terraformCloudSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Id()
	configPath := terraformCloudSecretBackendConfigPath(backend)

	backend, e = util.Remount(d, client, consts.FieldBackend, false)
	if e != nil {
		return e
	}

	if d.HasChange(consts.FieldDefaultLeaseTTL) || d.HasChange(consts.FieldMaxLeaseTTL) {
		defaultLeaseTTL := d.Get(consts.FieldDefaultLeaseTTL)
		maxLeaseTTL := d.Get(consts.FieldMaxLeaseTTL)
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultLeaseTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxLeaseTTL),
		}

		log.Printf("[DEBUG] Updating lease TTLs for %q", backend)
		if err := client.Sys().TuneMount(backend, config); err != nil {
			return fmt.Errorf("Error updating mount TTLs for %q: %s", backend, err)
		}

		d.Set(consts.FieldDefaultLeaseTTL, defaultLeaseTTL)
		d.Set(consts.FieldMaxLeaseTTL, maxLeaseTTL)
	}
	if d.HasChange(consts.FieldAddress) || d.HasChange(consts.FieldToken) || d.HasChange(consts.FieldBasePath) {
		log.Printf("[DEBUG] Updating Terraform Cloud configuration at %q", configPath)
		data := map[string]interface{}{
			consts.FieldAddress:  d.Get(consts.FieldAddress).(string),
			consts.FieldToken:    d.Get(consts.FieldToken).(string),
			consts.FieldBasePath: d.Get(consts.FieldBasePath).(string),
		}
		if _, err := client.Logical().Write(configPath, data); err != nil {
			return fmt.Errorf("Error configuring Terraform Cloud configuration for %q: %s", backend, err)
		}
		log.Printf("[DEBUG] Updated Terraform Cloud configuration at %q", configPath)
		d.Set(consts.FieldAddress, data[consts.FieldAddress])
		d.Set(consts.FieldToken, data[consts.FieldToken])
		d.Set(consts.FieldBasePath, data[consts.FieldBasePath])
	}

	if d.HasChange(consts.FieldTokenWOVersion) {
		tokenWO := d.Get(consts.FieldTokenWO).(string)
		log.Printf("[DEBUG] Updating write-only Terraform Cloud token for %q", backend)
		data := map[string]interface{}{
			consts.FieldTokenWO:  tokenWO,
			consts.FieldAddress:  d.Get(consts.FieldAddress).(string),
			consts.FieldBasePath: d.Get(consts.FieldBasePath).(string),
		}
		if _, err := client.Logical().Write(configPath, data); err != nil {
			return fmt.Errorf("Error configuring Terraform Cloud configuration for %q: %s", backend, err)
		}
	}

	return terraformCloudSecretBackendRead(d, meta)
}

func terraformCloudSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Id()

	log.Printf("[DEBUG] Unmounting Terraform Cloud backend %q", backend)
	err := client.Sys().Unmount(backend)
	if err != nil {
		return fmt.Errorf("Error unmounting Terraform Cloud backend from %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Unmounted Terraform Cloud backend %q", backend)
	return nil
}

func terraformCloudSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	backend := d.Id()

	log.Printf("[DEBUG] Checking if Terraform Cloud backend exists at %q", backend)

	_, err := mountutil.GetMount(context.Background(), client, backend)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			return false, nil
		}

		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}

	return true, nil
}

func terraformCloudSecretBackendConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config"
}
