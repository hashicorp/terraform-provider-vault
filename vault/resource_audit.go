package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func auditResource() *schema.Resource {
	return &schema.Resource{
		Create: auditWrite,
		Read:   auditRead,
		Delete: auditDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "Path in which to enable the audit device.",
			},
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Type of the audit device, such as 'file'.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Human-friendly description of the audit device.",
			},
			"local": {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Description: "Specifies if the audit device is a local only. Local audit devices are not replicated nor (if a secondary) removed by replication.",
			},
			"options": {
				Type:        schema.TypeMap,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Required:    true,
				ForceNew:    true,
				Description: "Configuration options to pass to the audit device itself.",
			},
		},
	}
}

func auditWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	description := d.Get("description").(string)
	local := d.Get("local").(bool)
	mountType := d.Get("type").(string)
	path := d.Get("path").(string)
	if path == "" {
		path = mountType
	}

	optionsRaw := d.Get("options").(map[string]interface{})
	options := make(map[string]string)

	for k, v := range optionsRaw {
		options[k] = v.(string)
	}

	log.Printf("[DEBUG] Enabling audit backend %s in Vault", path)
	opts := &api.EnableAuditOptions{
		Type:        mountType,
		Description: description,
		Local:       local,
		Options:     options,
	}

	if err := client.Sys().EnableAuditWithOptions(path, opts); err != nil {
		return fmt.Errorf("error enabling audit backend: %s", err)
	}

	d.SetId(path)

	return nil
}

func auditDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Unmounting %s from Vault", path)

	if err := client.Sys().DisableAudit(path); err != nil {
		return fmt.Errorf("error disabling audit backend Vault: %s", err)
	}

	return nil
}

func auditRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading audit backends %s from Vault", path)

	audits, err := client.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	// path can have a trailing slash, but doesn't need to have one
	// this standardises on having a trailing slash, which is how the
	// API always responds.
	audit, ok := audits[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Audit backend %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	// Local is not returned by the List operation
	d.Set("path", path)
	d.Set("type", audit.Type)
	d.Set("description", audit.Description)
	d.Set("options", audit.Options)

	return nil
}
