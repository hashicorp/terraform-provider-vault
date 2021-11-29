package vault

import (
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/vault/api"
)

func genericSecretMetadataDataSource() *schema.Resource {
	return &schema.Resource{
		Read: genericSecretMetadataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Full path from which a secret will be read.",
			},
			casRequiredKeyName: {
				Type:     schema.TypeBool,
				Computed: true,
			},
			customMetadataKeyName: {
				Type:     schema.TypeMap,
				Computed: true,
			},
			deleteVersionAfterKeyName: {
				Type:     schema.TypeString,
				Computed: true,
			},
			maxVersionsKeyName: {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},
			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},
			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},
			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func genericSecretMetadataSourceRead(d *schema.ResourceData, meta interface{}) error {
	path := d.Get("path").(string)
	client := meta.(*api.Client)
	secretMetadata, err := readKVMetadata(path, client)

	if err != nil {
		return err
	}
	d.SetId(path)
	d.Set(casRequiredKeyName, secretMetadata.Data[casRequiredKeyName].(bool))
	if val, ok := secretMetadata.Data[customMetadataKeyName]; ok {
		d.Set(customMetadataKeyName, val.(map[string]interface{}))
	}
	d.Set(deleteVersionAfterKeyName, secretMetadata.Data[deleteVersionAfterKeyName].(string))
	d.Set(maxVersionsKeyName, secretMetadata.Data[maxVersionsKeyName])

	d.Set("lease_id", secretMetadata.LeaseID)
	d.Set("lease_duration", secretMetadata.LeaseDuration)
	d.Set("lease_start_time", time.Now().UTC().Format(time.RFC3339))
	d.Set("lease_renewable", secretMetadata.Renewable)

	return nil
}
