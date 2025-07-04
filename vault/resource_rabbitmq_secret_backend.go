// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func rabbitMQSecretBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: rabbitMQSecretBackendCreate,
		ReadContext:   provider.ReadContextWrapper(rabbitMQSecretBackendRead),
		UpdateContext: rabbitMQSecretBackendUpdate,
		DeleteContext: rabbitMQSecretBackendDelete,
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

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
		consts.FieldDefaultLeaseTTL,
		consts.FieldMaxLeaseTTL,
	))

	return r
}

func rabbitMQSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	connectionUri := d.Get("connection_uri").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	verifyConnection := d.Get("verify_connection").(bool)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Rabbitmq backend at %q", path)
	if err := createMount(ctx, d, meta, client, path, consts.MountTypeRabbitMQ); err != nil {
		return diag.FromErr(err)
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
	_, err := client.Logical().Write(path+"/config/connection", data)
	if err != nil {
		return diag.Errorf("error configuring connection credentials for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote connection credentials to %q", path+"/config/connection")
	d.Partial(false)
	return rabbitMQSecretBackendRead(ctx, d, meta)
}

func rabbitMQSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	path := d.Id()

	log.Printf("[DEBUG] Reading RabbitMQ secret backend mount %q from Vault", path)
	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}
	if err := readMount(ctx, d, meta, true); err != nil {
		return diag.FromErr(err)
	}

	// the API can't serve the remaining fields

	return nil
}

func rabbitMQSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	d.Partial(true)

	if err := updateMount(ctx, d, meta, true); err != nil {
		return diag.FromErr(err)
	}
	path := d.Id()

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
			return diag.Errorf("error configuring connection credentials for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated root credentials at %q", path+"/config/connection")
	}
	d.Partial(false)
	return rabbitMQSecretBackendRead(ctx, d, meta)
}

func rabbitMQSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Unmounting RabbitMQ backend %q", path)
	err := client.Sys().UnmountWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error unmounting RabbitMQ backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted RabbitMQ backend %q", path)
	return nil
}
