// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func configUICustomMessageResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(configUICustomMessageCreate, provider.VaultVersion116),
		ReadContext:   configUICustomMessageRead,
		UpdateContext: configUICustomMessageUpdate,
		DeleteContext: configUICustomMessageDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique ID for the custom message",
			},
			consts.FieldTitle: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The title of the custom message",
			},
			consts.FieldMessageBase64: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The base64-encoded content of the custom message",
			},
			consts.FieldAuthenticated: {
				Type:     schema.TypeBool,
				Optional: true,

				Default:     true,
				Description: "A flag indicating whether the custom message is displayed pre-login (false) or post-login (true)",
			},
			consts.FieldType: {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "banner",
				ValidateDiagFunc: func(value interface{}, _ cty.Path) diag.Diagnostics {
					stringValue := value.(string)
					switch {
					case stringValue != "banner" && stringValue != "modal":
						return diag.Diagnostics{diag.Diagnostic{
							Severity: diag.Error,
							Summary:  "invalid value for \"type\" argument",
							Detail:   "The \"type\" argument can only be set to \"banner\" or \"modal\".",
						}}
					}

					return nil
				},
				Description: "The display type of custom message. Allowed values are banner and modal",
			},
			consts.FieldStartTime: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The starting time of the active period of the custom message",
			},
			consts.FieldEndTime: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The ending time of the active period of the custom message. Can be omitted for non-expiring message",
			},
			consts.FieldLink: {
				Type:     schema.TypeSet,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"title": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The title of the hyperlink",
						},
						"href": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The URL of the hyperlink",
						},
					},
				},
				Description: "A block containing a hyperlink associated with the custom message",
			},
			consts.FieldOptions: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "A map containing additional options for the custom message",
			},
		},
	}
}

func configUICustomMessageCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if !provider.IsEnterpriseSupported(meta) {
		return diag.Errorf("config_ui_custom_message is not supported by this version of vault")
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	secret, e := client.Sys().CreateUICustomMessageWithContext(ctx, buildUICustomMessageRequest(d))
	if e != nil {
		return diag.FromErr(e)
	}

	if secret == nil || secret.Data == nil {
		return diag.Errorf(`response from Vault server is empty`)
	}

	id, ok := secret.Data[consts.FieldID]
	if !ok {
		return diag.Errorf("error creating custom message: %s", secret.Data["error"])
	}

	d.SetId(id.(string))

	return configUICustomMessageRead(ctx, d, meta)
}

func configUICustomMessageRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	log.Printf("[DEBUG] Reading custom message %q", id)
	secret, e := client.Sys().ReadUICustomMessage(id)
	if e != nil {
		if util.Is404(e) {
			log.Printf("[DEBUG] custom message %q not found, removing from state", id)
			d.SetId("")
			return nil
		}
		return diag.FromErr(e)
	}

	if secret == nil || secret.Data == nil {
		log.Printf("[DEBUG] response from Vault server is empty for %q, removing from state", id)
		d.SetId("")
		return nil
	}

	secretData := secret.Data

	if _, ok := secretData["error"]; ok {
		errorList := secretData["error"].([]string)
		return diag.Errorf("errors received from Vault server: %s", errorList)
	}

	var endTimeValue string
	if v, ok := secretData[consts.FieldEndTime]; ok {
		if v != nil {
			endTimeValue = v.(string)
		}
	}

	var linkValue []map[string]interface{}

	if v, ok := secretData[consts.FieldLink]; ok {
		if v != nil {
			linkMap := v.(map[string]any)

			if len(linkMap) > 1 {
				return diag.Errorf(`invalid link specification: only a single link can be specified`)
			}

			for k, v := range linkMap {
				stringV, ok := v.(string)
				if !ok {
					return diag.Errorf("invalid href value in link specification: %v", v)
				}
				if len(k) > 0 && len(stringV) > 0 {
					linkValue = append(linkValue, map[string]interface{}{
						"title": k,
						"href":  stringV,
					},
					)
				}
				break
			}
		}
	}

	d.Set(consts.FieldTitle, secretData[consts.FieldTitle])
	d.Set(consts.FieldMessageBase64, secretData["message"])
	d.Set(consts.FieldAuthenticated, secretData[consts.FieldAuthenticated])
	d.Set(consts.FieldType, secretData[consts.FieldType])
	d.Set(consts.FieldStartTime, secretData[consts.FieldStartTime])
	d.Set(consts.FieldEndTime, endTimeValue)

	if linkValue != nil {
		d.Set(consts.FieldLink, linkValue)
	}

	d.Set(consts.FieldOptions, secretData[consts.FieldOptions])

	log.Printf("[DEBUG] Read custom message %q", id)
	return nil
}

func configUICustomMessageUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	if d.HasChanges(consts.FieldTitle, consts.FieldMessageBase64, consts.FieldAuthenticated, consts.FieldType, consts.FieldStartTime, consts.FieldEndTime, consts.FieldOptions, consts.FieldLink) {
		log.Printf("[DEBUG] Updating custom message %q", id)
		e = client.Sys().UpdateUICustomMessageWithContext(ctx, id, buildUICustomMessageRequest(d))
		if e != nil {
			return diag.FromErr(e)
		}
	}

	log.Printf("[DEBUG] Updated custom message %q", id)
	return configUICustomMessageRead(ctx, d, meta)
}

func configUICustomMessageDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	log.Printf("[DEBUG] Deleting custom message %q", id)
	e = client.Sys().DeleteUICustomMessageWithContext(ctx, id)
	if e != nil {
		return diag.Errorf("error deleting custom message %q: %s", id, e)
	}

	log.Printf("[DEBUG] Deleted custom message %q", id)
	return nil
}

func buildUICustomMessageRequest(d *schema.ResourceData) api.UICustomMessageRequest {
	request := api.UICustomMessageRequest{
		Title:         d.Get(consts.FieldTitle).(string),
		Message:       d.Get(consts.FieldMessageBase64).(string),
		Authenticated: d.Get(consts.FieldAuthenticated).(bool),
		Type:          d.Get(consts.FieldType).(string),
		StartTime:     d.Get(consts.FieldStartTime).(string),
		EndTime:       d.Get(consts.FieldEndTime).(string),
		Options:       d.Get(consts.FieldOptions).(map[string]interface{}),
	}

	linkValue := d.Get(consts.FieldLink).(*schema.Set)
	if linkValue.Len() == 1 {
		slice := linkValue.List()

		m := slice[0].(map[string]interface{})
		linkTitle := m["title"].(string)
		linkHref := m["href"].(string)

		request.WithLink(linkTitle, linkHref)
	}

	return request
}
