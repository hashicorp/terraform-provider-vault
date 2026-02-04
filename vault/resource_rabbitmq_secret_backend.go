// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

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
			consts.FieldDescription: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			consts.FieldDefaultLeaseTTLSeconds: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Default lease duration for secrets in seconds",
			},

			consts.FieldMaxLeaseTTLSeconds: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Maximum possible lease duration for secrets in seconds",
			},
			consts.FieldConnectionURI: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the RabbitMQ connection URI.",
			},
			consts.FieldUsername: {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Specifies the RabbitMQ management administrator username",
			},
			consts.FieldPassword: {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				Description:  "Specifies the RabbitMQ management administrator password",
				ExactlyOneOf: []string{consts.FieldPassword, consts.FieldPasswordWO},
			},
			consts.FieldPasswordWO: {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "Specifies the RabbitMQ management administrator password. This is a write-only field and will not be read back from Vault.",
				ExactlyOneOf: []string{consts.FieldPassword, consts.FieldPasswordWO},
			},
			consts.FieldPasswordWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "A version counter for the write-only password_wo field. Incrementing this value will trigger an update to the password.",
				RequiredWith: []string{consts.FieldPasswordWO},
			},
			consts.FieldVerifyConnection: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Specifies whether to verify connection URI, username, and password.",
			},
			consts.FieldPasswordPolicy: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a password policy to use when creating dynamic credentials. Defaults to generating an alphanumeric password if not set.",
			},
			consts.FieldUsernameTemplate: {
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
		consts.FieldDefaultLeaseTTLSeconds,
		consts.FieldMaxLeaseTTLSeconds,
	))

	return r
}

func rabbitMQSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)

	// Handle password and password_wo
	var password string
	if v, ok := d.GetOk(consts.FieldPassword); ok {
		password = v.(string)
	} else {
		p := cty.GetAttrPath(consts.FieldPasswordWO)
		woVal, _ := d.GetRawConfigAt(p)
		if !woVal.IsNull() {
			password = woVal.AsString()
		}
	}

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Rabbitmq backend at %q", path)
	if err := createMount(ctx, d, meta, client, path, consts.MountTypeRabbitMQ); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Mounted Rabbitmq backend at %q", path)
	d.SetId(path)

	log.Printf("[DEBUG] Writing connection credentials to %q", path+"/config/connection")
	data := map[string]interface{}{
		consts.FieldConnectionURI:    d.Get(consts.FieldConnectionURI).(string),
		consts.FieldUsername:         d.Get(consts.FieldUsername).(string),
		consts.FieldPassword:         password,
		consts.FieldVerifyConnection: d.Get(consts.FieldVerifyConnection).(bool),
		consts.FieldUsernameTemplate: d.Get(consts.FieldUsernameTemplate).(string),
		consts.FieldPasswordPolicy:   d.Get(consts.FieldPasswordPolicy).(string),
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
	if err := readMount(ctx, d, meta, true, false); err != nil {
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

	if err := updateMount(ctx, d, meta, true, false); err != nil {
		return diag.FromErr(err)
	}
	path := d.Id()

	if d.HasChanges(consts.FieldConnectionURI, consts.FieldUsername, consts.FieldPassword, consts.FieldPasswordWOVersion, consts.FieldVerifyConnection, consts.FieldUsernameTemplate, consts.FieldPasswordPolicy) {
		log.Printf("[DEBUG] Updating connection credentials at %q", path+"/config/connection")

		// Handle password and password_wo
		var password string
		if v, ok := d.GetOk(consts.FieldPassword); ok {
			password = v.(string)
		} else if d.HasChange(consts.FieldPasswordWOVersion) {
			woVal := d.GetRawConfig().GetAttr(consts.FieldPasswordWO)
			if !woVal.IsNull() {
				password = woVal.AsString()
			}
		}

		data := map[string]interface{}{
			consts.FieldConnectionURI:    d.Get(consts.FieldConnectionURI).(string),
			consts.FieldUsername:         d.Get(consts.FieldUsername).(string),
			consts.FieldPassword:         password,
			consts.FieldVerifyConnection: d.Get(consts.FieldVerifyConnection).(bool),
			consts.FieldUsernameTemplate: d.Get(consts.FieldUsernameTemplate).(string),
			consts.FieldPasswordPolicy:   d.Get(consts.FieldPasswordPolicy).(string),
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
