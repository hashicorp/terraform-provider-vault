// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func mfaTOTPResource() *schema.Resource {
	return &schema.Resource{
		Create: mfaTOTPWrite,
		Update: mfaTOTPUpdate,
		Delete: mfaTOTPDelete,
		Read:   provider.ReadWrapper(mfaTOTPRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "Name of the MFA method.",
				ValidateFunc: provider.ValidateNoTrailingSlash,
			},
			"issuer": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the key's issuing organization.",
			},
			"period": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     30,
				ForceNew:    true,
				Description: "The length of time used to generate a counter for the TOTP token calculation.",
			},
			"key_size": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     20,
				ForceNew:    true,
				Description: "Specifies the size in bytes of the generated key.",
			},
			"qr_size": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     200,
				ForceNew:    true,
				Description: "The pixel size of the generated square QR code.",
			},
			"algorithm": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "SHA1",
				ForceNew: true,
				Description: "Specifies the hashing algorithm used to generate the TOTP code. " +
					"Options include 'SHA1', 'SHA256' and 'SHA512'.",
			},
			"digits": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  6,
				ForceNew: true,
				Description: "The number of digits in the generated TOTP token. " +
					"This value can either be 6 or 8.",
			},
			"skew": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  1,
				ForceNew: true,
				Description: "The number of delay periods that are allowed when validating a TOTP token. " +
					"This value can either be 0 or 1.",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "ID computed by Vault.",
			},
		},
	}
}

func mfaTOTPPath(name string) string {
	return "sys/mfa/method/totp/" + strings.Trim(name, "/")
}

func mfaTOTPRequestData(d *schema.ResourceData) map[string]interface{} {
	data := map[string]interface{}{}

	fields := []string{
		"name", "issuer", "period",
		"key_size", "qr_size", "algorithm",
		"digits", "skew",
	}

	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	return data
}

func mfaTOTPWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Get("name").(string)
	path := mfaTOTPPath(name)

	log.Printf("[DEBUG] Creating mfaTOTP %s in Vault", name)
	_, err := client.Logical().Write(path, mfaTOTPRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing to Vault at %s, err=%w", path, err)
	}

	d.SetId(name)

	return mfaTOTPRead(d, meta)
}

func mfaTOTPRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	name := d.Id()
	path := mfaTOTPPath(name)

	log.Printf("[DEBUG] Reading MFA TOTP config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault at %s, err=%w", path, err)
	}

	fields := []string{
		"name", "issuer", "period",
		"key_size", "qr_size", "algorithm",
		"digits", "skew", "id",
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return err
		}
	}

	return nil
}

func mfaTOTPUpdate(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func mfaTOTPDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := mfaTOTPPath(d.Id())

	log.Printf("[DEBUG] Deleting mfaTOTP %s from Vault", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting from Vault at %s, err=%w", path, err)
	}

	return nil
}
