package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var passwordPolicyAttributes = []string{"policy"}

func passwordPolicyResource() *schema.Resource {
	return &schema.Resource{
		Create: resourcePasswordPolicyWrite,
		Update: resourcePasswordPolicyWrite,
		Delete: resourcePasswordPolicyDelete,
		Read:   resourcePasswordPolicyRead,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the password policy.",
			},

			"policy": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The password policy document",
			},
		},
	}
}

func resourcePasswordPolicyWrite(d *schema.ResourceData, meta interface{}) error {
	return passwordPolicyWrite(passwordPolicyAttributes, d, meta)
}

func resourcePasswordPolicyDelete(d *schema.ResourceData, meta interface{}) error {
	return passwordPolicyDelete(d, meta)
}

func resourcePasswordPolicyRead(d *schema.ResourceData, meta interface{}) error {
	return passwordPolicyRead(passwordPolicyAttributes, d, meta)
}
