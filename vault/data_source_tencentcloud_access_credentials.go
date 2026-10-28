// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func tencentCloudAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(tencentCloudAccessCredentialsDataSourceRead),

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Tencent cloud Secret Backend to read credentials from.",
			},

			"role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Tencent cloud Secret Role to read credentials from.",
			},

			"secret_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Tencent cloud secret ID read from Vault.",
			},

			"secret_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Tencent cloud secret key read from Vault.",
			},

			"token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Tencent cloud security token read from Vault. (Only returned if type is 'sts').",
			},

			consts.FieldLeaseID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},

			consts.FieldLeaseDuration: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},

			consts.FieldLeaseRenewable: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func tencentCloudAccessCredentialsDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	credType := "creds"
	role := d.Get("role").(string)
	path := backend + "/" + credType + "/" + role

	data := map[string][]string{}

	log.Printf("[DEBUG] Reading %q from Vault with data %#v", path, data)
	secret, err := client.Logical().ReadWithData(path, data)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if secret == nil {
		return fmt.Errorf("no role found at path %q", path)
	}

	secretId := secret.Data["secret_id"].(string)
	secretKey := secret.Data["secret_key"].(string)
	var token string
	if secret.Data["token"] != nil {
		token = secret.Data["token"].(string)
	}

	d.SetId(secret.LeaseID)
	_ = d.Set("secret_id", secretId)
	_ = d.Set("secret_key", secretKey)
	_ = d.Set("token", token)
	_ = d.Set(consts.FieldLeaseID, secret.LeaseID)
	_ = d.Set(consts.FieldLeaseDuration, secret.LeaseDuration)
	_ = d.Set(consts.FieldLeaseRenewable, secret.Renewable)

	return nil
}
