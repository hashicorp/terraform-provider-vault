package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func githubAuthBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"path": {
			Type:        schema.TypeString,
			Optional:    true,
			ForceNew:    true,
			Description: "Path where the auth backend is mounted",
			Default:     "github",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"organization": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The organization users must be part of.",
		},
		"base_url": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "The API endpoint to use. Useful if you are running GitHub Enterprise or an API-compatible authentication server.",
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Specifies the description of the mount. This overrides the current stored value, if any.",
		},
		"ttl": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Duration after which authentication will be expired, in seconds.",
			ValidateFunc:  validateDuration,
			Deprecated:    "use `token_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_ttl"},
		},
		"max_ttl": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Maximum duration after which authentication will be expired, in seconds.",
			ValidateFunc:  validateDuration,
			Deprecated:    "use `token_max_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_max_ttl"},
		},
		"accessor": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The mount accessor related to the auth mount.",
		},
		"tune": authMountTuneSchema(),
	}

	addTokenFields(fields, &addTokenFieldsConfig{
		TokenMaxTTLConflict: []string{"max_ttl"},
		TokenTTLConflict:    []string{"ttl"},
	})

	return &schema.Resource{
		Create: githubAuthBackendCreate,
		Read:   githubAuthBackendRead,
		Update: githubAuthBackendUpdate,
		Delete: githubAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func githubAuthBackendCreate(d *schema.ResourceData, meta interface{}) error {
	var description string

	client := meta.(*api.Client)
	path := strings.Trim(d.Get("path").(string), "/")

	if v, ok := d.GetOk("description"); ok {
		description = v.(string)
	}

	log.Printf("[DEBUG] Enabling github auth backend at '%s'", path)
	err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
		Type:        "github",
		Description: description,
	})

	if err != nil {
		return fmt.Errorf("error enabling github auth backend at '%s': %s", path, err)
	}
	log.Printf("[INFO] Enabled github auth backend at '%s'", path)

	d.SetId(path)
	d.MarkNewResource()
	d.Partial(true)
	d.SetPartial("path")
	return githubAuthBackendUpdate(d, meta)
}

func githubAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := "auth/" + d.Id()
	configPath := path + "/config"

	data := map[string]interface{}{}

	if v, ok := d.GetOk("organization"); ok {
		data["organization"] = v.(string)
	}
	if v, ok := d.GetOk("base_url"); ok {
		data["base_url"] = v.(string)
	}
	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	updateTokenFields(d, data, false)

	// Check if the user is using the deprecated `ttl`
	if _, deprecated := d.GetOk("ttl"); deprecated {
		// Then we see if `token_ttl` was set and unset it
		// Vault will still return `ttl`
		if _, ok := d.GetOk("token_ttl"); ok {
			d.Set("token_ttl", nil)
		}
	}

	// Check if the user is using the deprecated `max_ttl`
	if _, deprecated := d.GetOk("max_ttl"); deprecated {
		// Then we see if `token_max_ttl` was set and unset it
		// Vault will still return `max_ttl`
		if _, ok := d.GetOk("token_max_ttl"); ok {
			d.Set("token_max_ttl", nil)
		}
	}

	log.Printf("[DEBUG] Writing github auth config to '%q'", configPath)
	_, err := client.Logical().Write(configPath, data)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing github config to '%q': %s", configPath, err)
	}
	log.Printf("[INFO] Github auth config successfully written to '%q'", configPath)

	d.SetPartial("organization")
	d.SetPartial("base_url")
	if _, ok := data["ttl"]; ok {
		d.SetPartial("ttl")
	}
	if _, ok := data["max_ttl"]; ok {
		d.SetPartial("max_ttl")
	}

	if d.HasChange("tune") {
		log.Printf("[INFO] Github Auth '%q' tune configuration changed", d.Id())
		if raw, ok := d.GetOk("tune"); ok {
			log.Printf("[DEBUG] Writing github auth tune to '%q'", path)

			err := authMountTune(client, path, raw)
			if err != nil {
				return nil
			}

			log.Printf("[INFO] Written github auth tune to '%q'", path)
			d.SetPartial("tune")
		}
	}

	if d.HasChange("description") {
		description := d.Get("description").(string)
		tune := api.MountConfigInput{Description: &description}
		err := client.Sys().TuneMount(path, tune)
		if err != nil {
			log.Printf("[ERROR] Error updating github auth description to '%q'", path)
			return err
		}
		d.SetPartial("description")
	}

	d.Partial(false)
	return githubAuthBackendRead(d, meta)
}

func githubAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := "auth/" + d.Id()
	configPath := path + "/config"

	log.Printf("[DEBUG] Reading github auth mount from '%q'", path)
	mount, err := authMountInfoGet(client, d.Id())
	if err != nil {
		return fmt.Errorf("error reading github auth mount from '%q': %s", path, err)
	}
	log.Printf("[INFO] Read github auth mount from '%q'", path)

	log.Printf("[DEBUG] Reading github auth config from '%q'", configPath)
	dt, err := client.Logical().Read(configPath)
	if err != nil {
		return fmt.Errorf("error reading github auth config from '%q': %s", configPath, err)
	}
	log.Printf("[INFO] Read github auth config from '%q'", configPath)

	if dt == nil {
		log.Printf("[WARN] Github auth config from '%q' not found, removing from state", configPath)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Reading github auth tune from '%q/tune'", path)
	tune, err := client.Sys().MountConfig(path)
	if err != nil {
		log.Printf("[ERROR] Error when reading tune config from path '%q/tune': %s", path, err)
		return err
	}

	rawTune := flattenAuthMethodTune(tune)
	if err := d.Set("tune", []map[string]interface{}{rawTune}); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path '%q/tune' to state: %s", path, err)
		return err
	}

	log.Printf("[INFO] Read github auth tune from '%q/tune'", path)

	authMount, err := authMountInfoGet(client, d.Id())
	if err != nil {
		return err
	}
	ttlS := flattenVaultDuration(dt.Data["ttl"])
	maxTtlS := flattenVaultDuration(dt.Data["max_ttl"])

	readTokenFields(d, dt)

	// Check if the user is using the deprecated `ttl`
	if _, deprecated := d.GetOk("ttl"); deprecated {
		// Then we see if `token_ttl` was set and unset it
		// Vault will still return `ttl`
		if _, ok := d.GetOk("token_ttl"); ok {
			d.Set("token_ttl", nil)
		}

		d.Set("ttl", ttlS)
	}

	// Check if the user is using the deprecated `max_ttl`
	if _, deprecated := d.GetOk("max_ttl"); deprecated {
		// Then we see if `token_max_ttl` was set and unset it
		// Vault will still return `max_ttl`
		if _, ok := d.GetOk("token_max_ttl"); ok {
			d.Set("token_max_ttl", nil)
		}

		d.Set("max_ttl", maxTtlS)
	}

	d.Set("path", d.Id())
	d.Set("organization", dt.Data["organization"])
	d.Set("base_url", dt.Data["base_url"])
	d.Set("description", authMount.Description)
	d.Set("accessor", mount.Accessor)

	return nil
}

func githubAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	return authMountDisable(meta.(*api.Client), d.Id())
}
