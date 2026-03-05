// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	automatedrotationutil "github.com/hashicorp/terraform-provider-vault/internal/rotation"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

const (
	gcpAuthType        = "gcp"
	gcpAuthDefaultPath = "gcp"

	fieldAPI     = "api"
	fieldIAM     = "iam"
	fieldCRM     = "crm"
	fieldCompute = "compute"
)

func gcpAuthBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: gcpAuthBackendWrite,
		UpdateContext: gcpAuthBackendUpdate,
		ReadContext:   provider.ReadContextWrapper(gcpAuthBackendRead),
		DeleteContext: gcpAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Schema: map[string]*schema.Schema{
			consts.FieldCredentials: {
				Type:          schema.TypeString,
				StateFunc:     NormalizeCredentials,
				ValidateFunc:  ValidateCredentials,
				Sensitive:     true,
				Optional:      true,
				ConflictsWith: []string{consts.FieldCredentialsWO},
			},
			consts.FieldCredentialsWO: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "JSON-encoded credentials to use to connect to GCP. This field is write-only and the value cannot be read back.",
				Sensitive:     true,
				WriteOnly:     true,
				ConflictsWith: []string{consts.FieldCredentials},
			},
			consts.FieldCredentialsWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "A version counter for write-only credentials. Incrementing this value will cause the provider to send the credentials to Vault.",
				RequiredWith: []string{consts.FieldCredentialsWO},
			},
			consts.FieldDescription: {
				Type:     schema.TypeString,
				Optional: true,
			},
			consts.FieldClientID: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			consts.FieldPrivateKeyID: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			consts.FieldProjectID: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			consts.FieldClientEmail: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			consts.FieldPath: {
				Type:     schema.TypeString,
				Optional: true,
				Default:  gcpAuthDefaultPath,
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldLocal: {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Description: "Specifies if the auth method is local only",
			},
			consts.FieldCustomEndpoint: {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Description: "Specifies overrides to service endpoints used when making API requests to GCP.",
				Elem: &schema.Resource{
					Schema: gcpAuthCustomEndpointSchema(),
				},
			},
			consts.FieldAccessor: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},
			consts.FieldIdentityTokenAudience: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience claim value for plugin identity tokens.",
			},
			consts.FieldIdentityTokenTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The TTL of generated tokens.",
			},
			consts.FieldIdentityTokenKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The key to use for signing identity tokens.",
			},
			consts.FieldServiceAccountEmail: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Service Account to impersonate for plugin workload identity federation.",
			},
			consts.FieldIAMAlias: {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "Defines what alias needs to be used during login and refelects the same in token metadata and audit logs.",
				ValidateFunc: validation.StringInSlice([]string{"role_id", "unique_id"}, false),
			},
			consts.FieldIAMMetadata: {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Description: "Controls the metadata to include on the token returned by the login endpoint.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldGceAlias: {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "Defines what alias needs to be used during login and refelects the same in token metadata and audit logs.",
				ValidateFunc: validation.StringInSlice([]string{"role_id", "instance_id"}, false),
			},
			consts.FieldGceMetadata: {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Description: "Controls which instance metadata fields from the GCE login are captured into Vault's token metadata or audit logs.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldTune: authMountTuneSchema(),
		},
	}, false)

	// Add common automated root rotation schema to the resource.
	provider.MustAddSchema(r, provider.GetAutomatedRootRotationSchema())

	return r
}

func gcpAuthCustomEndpointSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		fieldAPI: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Replaces the service endpoint used in API requests " +
				"to https://www.googleapis.com.",
		},
		fieldIAM: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Replaces the service endpoint used in API requests " +
				"to `https://iam.googleapis.com`.",
		},
		fieldCRM: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Replaces the service endpoint used in API requests " +
				"to `https://cloudresourcemanager.googleapis.com`.",
		},
		fieldCompute: {
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

func gcpAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	authType := gcpAuthType
	path := d.Get(consts.FieldPath).(string)
	desc := d.Get(consts.FieldDescription).(string)
	local := d.Get(consts.FieldLocal).(bool)

	config := &api.MountConfigInput{}
	useAPIver117Ent := provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta)
	if useAPIver117Ent {
		if v, ok := d.GetOk(consts.FieldIdentityTokenKey); ok {
			config.IdentityTokenKey = v.(string)
		}
	}

	log.Printf("[DEBUG] Enabling gcp auth backend %q", path)
	err := client.Sys().EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type:        authType,
		Description: desc,
		Local:       local,
		Config:      *config,
	})
	if err != nil {
		return diag.Errorf("error enabling gcp auth backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled gcp auth backend %q", path)

	d.SetId(path)

	return gcpAuthBackendUpdate(ctx, d, meta)
}

func gcpAuthBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	gcpPath := d.Id()
	gcpAuthPath := "auth/" + gcpPath
	path := gcpAuthBackendConfigPath(gcpPath)
	useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta)
	useAPIVer119Ent := provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta)

	if !d.IsNewResource() {
		newMount, err := util.Remount(d, client, consts.FieldPath, true)
		if err != nil {
			return diag.FromErr(err)
		}

		gcpAuthPath = "auth/" + newMount
		path = gcpAuthBackendConfigPath(newMount)

		if d.HasChanges(consts.FieldIdentityTokenKey, consts.FieldDescription) {
			desc := d.Get(consts.FieldDescription).(string)
			config := api.MountConfigInput{
				Description: &desc,
			}
			if useAPIVer117Ent {
				config.IdentityTokenKey = d.Get(consts.FieldIdentityTokenKey).(string)
			}
			if err := client.Sys().TuneMountWithContext(ctx, path, config); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	data := map[string]interface{}{}

	var credentials string
	if v, ok := d.GetOk(consts.FieldCredentials); ok {
		if d.HasChange(consts.FieldCredentials) {
			credentials = v.(string)
		}
	} else if d.HasChange(consts.FieldCredentialsWOVersion) {
		credWo, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldCredentialsWO))
		if !credWo.IsNull() {
			credentials = credWo.AsString()
		}
	}

	if credentials != "" {
		data[consts.FieldCredentials] = credentials
	}

	epField := consts.FieldCustomEndpoint
	if d.HasChange(epField) {
		endpoints := make(map[string]interface{})
		for epKey := range gcpAuthCustomEndpointSchema() {
			key := fmt.Sprintf("%s.%d.%s", epField, 0, epKey)
			if d.HasChange(key) {
				endpoints[epKey] = d.Get(key)
			}
		}
		data[consts.FieldCustomEndpoint] = endpoints
	}

	if d.HasChange(consts.FieldTune) {
		log.Printf("[DEBUG] %s Auth %q tune configuration changed", gcpAuthType, gcpAuthPath)
		if raw, ok := d.GetOk(consts.FieldTune); ok {
			log.Printf("[DEBUG] Writing %s auth tune to %q", gcpAuthType, gcpAuthPath)

			if err := authMountTune(ctx, client, gcpAuthPath, raw); err != nil {
				return nil
			}

			log.Printf("[DEBUG] Written %s auth tune to '%q'", gcpAuthType, gcpAuthPath)
		}
	}

	if d.HasChange(consts.FieldDescription) {
		description := d.Get(consts.FieldDescription).(string)
		tune := api.MountConfigInput{Description: &description}
		err := client.Sys().TuneMountWithContext(ctx, gcpAuthPath, tune)
		if err != nil {
			log.Printf("[ERROR] Error updating %s auth description at %q", gcpAuthType, gcpAuthPath)
			return diag.FromErr(err)
		}
	}

	if useAPIVer117Ent {
		fields := []string{
			consts.FieldIdentityTokenAudience,
			consts.FieldIdentityTokenTTL,
			consts.FieldServiceAccountEmail,
		}

		for _, k := range fields {
			if v, ok := d.GetOk(k); ok {
				data[k] = v
			}
		}
	}

	// Add IAM alias, IAM Metadata, GCE alias and GCE Metadata if provided
	if iamMetadataConfig, ok := d.GetOk(consts.FieldIAMMetadata); ok {
		data[consts.FieldIAMMetadata] = util.TerraformSetToStringArray(iamMetadataConfig)
	}

	if gceMetadataConfig, ok := d.GetOk(consts.FieldGceMetadata); ok {
		data[consts.FieldGceMetadata] = util.TerraformSetToStringArray(gceMetadataConfig)
	}

	fields := []string{
		consts.FieldIAMAlias,
		consts.FieldGceAlias,
	}

	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	if useAPIVer119Ent {
		// Parse automated root rotation fields if running Vault Enterprise 1.19 or newer.
		automatedrotationutil.ParseAutomatedRotationFields(d, data)
	}

	log.Printf("[DEBUG] Writing %s config at path %q", gcpAuthType, path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("error writing gcp config %q: %s", path, err)
	}

	log.Printf("[DEBUG] Wrote gcp config %q", path)

	return gcpAuthBackendRead(ctx, d, meta)
}

func gcpAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	gcpPath := d.Id()
	gcpAuthPath := "auth/" + gcpPath
	path := gcpAuthBackendConfigPath(gcpPath)

	log.Printf("[DEBUG] Reading gcp auth backend config %q", path)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading gcp auth backend config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read gcp auth backend config %q", path)

	if resp == nil {
		log.Printf("[WARN] gcp auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	params := []string{
		consts.FieldPrivateKeyID,
		consts.FieldClientID,
		consts.FieldProjectID,
		consts.FieldClientEmail,
		consts.FieldLocal,
		consts.FieldIAMAlias,
		consts.FieldIAMMetadata,
		consts.FieldGceAlias,
		consts.FieldGceMetadata,
	}

	if provider.IsEnterpriseSupported(meta) {
		if provider.IsAPISupported(meta, provider.VaultVersion117) {
			params = append(params,
				consts.FieldIdentityTokenAudience,
				consts.FieldIdentityTokenTTL,
				consts.FieldServiceAccountEmail,
			)
		}

		if provider.IsAPISupported(meta, provider.VaultVersion119) {
			params = append(params, automatedrotationutil.AutomatedRotationFields...)
		}
	}

	for _, param := range params {
		if err := d.Set(param, resp.Data[param]); err != nil {
			return diag.FromErr(err)
		}
	}

	if endpointsRaw, ok := resp.Data[consts.FieldCustomEndpoint]; ok {
		endpoints, ok := endpointsRaw.(map[string]interface{})
		if !ok {
			return diag.Errorf("custom_endpoint has unexpected type %T, path=%q", endpointsRaw, path)
		}
		if err := d.Set(consts.FieldCustomEndpoint, []map[string]interface{}{endpoints}); err != nil {
			return diag.FromErr(err)
		}
	}

	mount, err := mountutil.GetAuthMount(ctx, client, gcpPath)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", gcpPath)
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading %s auth tune from '%s/tune'", gcpAuthType, gcpAuthPath)
	rawTune, err := authMountTuneGet(ctx, client, gcpAuthPath)
	if err != nil {
		return diag.Errorf("error reading tune information from Vault: %s", err)
	}
	input, err := retrieveMountConfigInput(d)
	if err != nil {
		return diag.Errorf("error retrieving tune configuration from state: %s", err)
	}
	mergedTune := mergeAuthMethodTune(rawTune, input)
	if err := d.Set(consts.FieldTune, mergedTune); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path '%s/tune' to state: %s", gcpAuthPath, err)
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldAccessor, mount.Accessor); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldDescription, mount.Description); err != nil {
		return diag.FromErr(err)
	}
	// set the auth backend's path
	if err := d.Set(consts.FieldPath, gcpPath); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func gcpAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting gcp auth backend %q", path)
	err := client.Sys().DisableAuthWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting gcp auth backend %q: %q", path, err)
	}
	log.Printf("[DEBUG] Deleted gcp auth backend %q", path)

	return nil
}
