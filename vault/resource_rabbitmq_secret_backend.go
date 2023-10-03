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

func rabbitMQSecretBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		Create:        rabbitMQSecretBackendCreate,
		Read:          provider.ReadWrapper(rabbitMQSecretBackendRead),
		Update:        rabbitMQSecretBackendUpdate,
		Delete:        rabbitMQSecretBackendDelete,
		Exists:        rabbitMQSecretBackendExists,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "rabbitmq",
				Description: "The path of the RabbitMQ Secret Backend where the connection should be configured",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Default lease duration for secrets in seconds",
			},

			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Maximum possible lease duration for secrets in seconds",
			},
			"connection_uri": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the RabbitMQ connection URI.",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Specifies the RabbitMQ management administrator username",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Specifies the RabbitMQ management administrator password",
			},
			"verify_connection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Specifies whether to verify connection URI, username, and password.",
			},
			"password_policy": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a password policy to use when creating dynamic credentials. Defaults to generating an alphanumeric password if not set.",
			},
			"username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Template describing how dynamic usernames are generated.",
			},
		},
	}, false)
}

func rabbitMQSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get(consts.FieldPath).(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)
	connectionUri := d.Get("connection_uri").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	verifyConnection := d.Get("verify_connection").(bool)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Rabbitmq backend at %q", path)
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        consts.MountTypeRabbitMQ,
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted Rabbitmq backend at %q", path)
	d.SetId(path)

	log.Printf("[DEBUG] Writing connection credentials to %q", path+"/config/connection")
	data := map[string]interface{}{
		"connection_uri":    connectionUri,
		"username":          username,
		"password":          password,
		"verify_connection": verifyConnection,
		"username_template": d.Get("username_template").(string),
		"password_policy":   d.Get("password_policy").(string),
	}
	_, err = client.Logical().Write(path+"/config/connection", data)
	if err != nil {
		return fmt.Errorf("error configuring connection credentials for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote connection credentials to %q", path+"/config/connection")
	d.Partial(false)
	return rabbitMQSecretBackendRead(d, meta)
}

func rabbitMQSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Reading RabbitMQ secret backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read RabbitMQ secret backend mount %q from Vault", path)
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing backend from state.", path)
		d.SetId("")
		return nil
	}
	d.Set(consts.FieldPath, path)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)

	// access key, secret key, and region, sadly, we can't read out
	// the API doesn't support it
	// So... if they drift, they drift.

	return nil
}

func rabbitMQSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	d.Partial(true)

	path, err := util.Remount(d, client, consts.FieldPath, false)
	if err != nil {
		return err
	}

	if d.HasChanges("default_lease_ttl_seconds", "max_lease_ttl_seconds") {
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		}
		log.Printf("[DEBUG] Updating lease TTLs for %q", path)
		err := client.Sys().TuneMount(path, config)
		if err != nil {
			return fmt.Errorf("error updating mount TTLs for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated lease TTLs for %q", path)
	}
	if d.HasChanges("connection_uri", "username", "password", "verify_connection", "username_template", "password_policy") {
		log.Printf("[DEBUG] Updating connection credentials at %q", path+"/config/connection")
		data := map[string]interface{}{
			"connection_uri":    d.Get("connection_uri").(string),
			"username":          d.Get("username").(string),
			"password":          d.Get("password").(string),
			"verify_connection": d.Get("verify_connection").(bool),
			"username_template": d.Get("username_template").(string),
			"password_policy":   d.Get("password_policy").(string),
		}
		_, err := client.Logical().Write(path+"/config/connection", data)
		if err != nil {
			return fmt.Errorf("error configuring connection credentials for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated root credentials at %q", path+"/config/connection")
	}
	d.Partial(false)
	return rabbitMQSecretBackendRead(d, meta)
}

func rabbitMQSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Unmounting RabbitMQ backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error unmounting RabbitMQ backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted RabbitMQ backend %q", path)
	return nil
}

func rabbitMQSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if RabbitMQ backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if RabbitMQ backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}
