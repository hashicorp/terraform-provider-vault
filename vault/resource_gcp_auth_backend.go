// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	gcpAuthType        = "gcp"
	gcpAuthDefaultPath = "gcp"
)

func gcpAuthBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		Create: gcpAuthBackendWrite,
		Update: gcpAuthBackendUpdate,
		Read:   provider.ReadWrapper(gcpAuthBackendRead),
		Delete: gcpAuthBackendDelete,
		Exists: gcpAuthBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Schema: map[string]*schema.Schema{
			"credentials": {
				Type:         schema.TypeString,
				StateFunc:    NormalizeCredentials,
				ValidateFunc: ValidateCredentials,
				Sensitive:    true,
				Optional:     true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"client_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"private_key_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"project_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"client_email": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"path": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  gcpAuthDefaultPath,
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Description: "Specifies if the auth method is local only",
			},
			"custom_endpoint": {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Description: "Specifies overrides to service endpoints used when making API requests to GCP.",
				Elem: &schema.Resource{
					Schema: gcpAuthCustomEndpointSchema(),
				},
			},
			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},
			"tune": authMountTuneSchema(),
		},
	}, false)
}

func gcpAuthCustomEndpointSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"api": {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Replaces the service endpoint used in API requests " +
				"to https://www.googleapis.com.",
		},
		"iam": {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Replaces the service endpoint used in API requests " +
				"to `https://iam.googleapis.com`.",
		},
		"crm": {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Replaces the service endpoint used in API requests " +
				"to `https://cloudresourcemanager.googleapis.com`.",
		},
		"compute": {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Replaces the service endpoint used in API requests " +
				"to `https://compute.googleapis.com`.",
		},
	}
}

func ValidateCredentials(configI interface{}, k string) ([]string, []error) {
	credentials := configI.(string)
	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(credentials), &dataMap)
	if err != nil {
		return nil, []error{err}
	}
	return nil, nil
}

func NormalizeCredentials(configI interface{}) string {
	credentials := configI.(string)

	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(credentials), &dataMap)
	if err != nil {
		// The validate function should've taken care of this.
		log.Printf("[ERROR] Invalid JSON data in vault_gcp_auth_backend: %s", err)
		return ""
	}

	ret, err := json.Marshal(dataMap)
	if err != nil {
		// Should never happen.
		log.Printf("[ERROR] Problem normalizing JSON for vault_gcp_auth_backend: %s", err)
		return credentials
	}

	return string(ret)
}

func gcpAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}

func gcpAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	authType := gcpAuthType
	path := d.Get("path").(string)
	desc := d.Get("description").(string)
	local := d.Get("local").(bool)

	log.Printf("[DEBUG] Enabling gcp auth backend %q", path)
	err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
		Type:        authType,
		Description: desc,
		Local:       local,
	})
	if err != nil {
		return fmt.Errorf("error enabling gcp auth backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled gcp auth backend %q", path)

	d.SetId(path)

	return gcpAuthBackendUpdate(d, meta)
}

func gcpAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	gcpPath := d.Id()
	path := gcpAuthBackendConfigPath(gcpPath)

	if !d.IsNewResource() {
		newMount, err := util.Remount(d, client, consts.FieldPath, true)
		if err != nil {
			return err
		}

		path = gcpAuthBackendConfigPath(newMount)
	}

	data := map[string]interface{}{}

	if v, ok := d.GetOk("credentials"); ok {
		data["credentials"] = v
	}

	epField := "custom_endpoint"
	if d.HasChange(epField) {
		endpoints := make(map[string]interface{})
		for epKey := range gcpAuthCustomEndpointSchema() {
			key := fmt.Sprintf("%s.%d.%s", epField, 0, epKey)
			if d.HasChange(key) {
				endpoints[epKey] = d.Get(key)
			}
		}
		data["custom_endpoint"] = endpoints
	}

	log.Printf("[DEBUG] Writing gcp config %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing gcp config %q: %s", path, err)
	}

	backendType := gcpAuthType
	var input api.MountConfigInput
	var callTune bool

	if d.HasChange("tune") {
		log.Printf("[INFO] Auth '%q' tune configuration changed", gcpPath)

		if raw, ok := d.GetOk("tune"); ok {
			log.Printf("[DEBUG] Writing %s auth tune to '%q'", backendType, gcpPath)

			input = expandAuthMethodTune(raw.(*schema.Set).List())
		}
		callTune = true
	}

	if d.HasChange("description") && !d.IsNewResource() {
		desc := d.Get("description").(string)
		input.Description = &desc
		callTune = true
	}

	if callTune {
		if err := tuneMount(client, "auth/"+gcpPath, input); err != nil {
			return err
		}

		log.Printf("[INFO] Written %s auth tune to '%q'", backendType, gcpPath)
	}
	log.Printf("[DEBUG] Wrote gcp config %q", path)

	return gcpAuthBackendRead(d, meta)
}

func gcpAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := gcpAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Reading gcp auth backend config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading gcp auth backend config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read gcp auth backend config %q", path)

	if resp == nil {
		log.Printf("[WARN] gcp auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	params := []string{
		"private_key_id",
		"client_id",
		"project_id",
		"client_email",
		"local",
	}

	for _, param := range params {
		if err := d.Set(param, resp.Data[param]); err != nil {
			return err
		}
	}

	if endpointsRaw, ok := resp.Data["custom_endpoint"]; ok {
		endpoints, ok := endpointsRaw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("custom_endpoint has unexpected type %T, path=%q", endpointsRaw, path)
		}
		if err := d.Set("custom_endpoint", []map[string]interface{}{endpoints}); err != nil {
			return err
		}
	}
	// fetch AuthMount in order to set accessor attribute
	mount, err := getAuthMountIfPresent(client, d.Id())
	if err != nil {
		return err
	}
	if mount == nil {
		d.SetId("")
		return nil
	}
	if err := d.Set("accessor", mount.Accessor); err != nil {
		return err
	}

	// set the auth backend's path
	if err := d.Set("path", d.Id()); err != nil {
		return err
	}

	return nil
}

func gcpAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting gcp auth backend %q", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("error deleting gcp auth backend %q: %q", path, err)
	}
	log.Printf("[DEBUG] Deleted gcp auth backend %q", path)

	return nil
}

func gcpAuthBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := gcpAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Checking if gcp auth backend %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of gcp config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if gcp auth backend %q exists", path)

	return resp != nil, nil
}
