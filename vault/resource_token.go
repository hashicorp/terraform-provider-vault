// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func tokenResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenCreate,
		Read:   provider.ReadWrapper(tokenRead),
		Update: tokenUpdate,
		Delete: tokenDelete,
		Exists: tokenExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldRoleName: {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The token role name.",
			},
			consts.FieldPolicies: {
				Type:     schema.TypeSet,
				Required: false,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of policies.",
			},
			consts.FieldNoParent: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Flag to create a token without parent.",
			},
			consts.FieldNoDefaultPolicy: {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "Flag to disable the default policy.",
			},
			consts.FieldRenewable: {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Flag to allow the token to be renewed",
			},
			consts.FieldTTL: {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The TTL period of the token.",
			},
			consts.FieldExplicitMaxTTL: {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The explicit max TTL of the token.",
			},
			consts.FieldWrappingTTL: {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The TTL period of the wrapped token.",
			},
			consts.FieldDisplayName: {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     consts.FieldToken,
				Description: "The display name of the token.",
			},
			consts.FieldNumUses: {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "The number of allowed uses of the token.",
			},
			consts.FieldPeriod: {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The period of the token.",
			},
			consts.FieldRenewMinLease: {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The minimum lease to renew token.",
			},
			consts.FieldRenewIncrement: {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The renew increment.",
			},
			consts.FieldLeaseDuration: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The token lease duration.",
			},
			consts.FieldLeaseStarted: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The token lease started on.",
			},
			consts.FieldClientToken: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client token.",
				Sensitive:   true,
			},
			consts.FieldWrappedToken: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client wrapped token.",
				Sensitive:   true,
			},
			consts.FieldWrappingAccessor: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client wrapping accessor.",
				Sensitive:   true,
			},
			consts.FieldMetadata: {
				Type:        schema.TypeMap,
				Optional:    true,
				ForceNew:    true,
				Description: "Metadata to be associated with the token.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func tokenCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	var err error
	var wrapped bool

	role := d.Get(consts.FieldRoleName).(string)

	createRequest := &api.TokenCreateRequest{}
	if v, ok := d.GetOk(consts.FieldPolicies); ok && v != nil {
		createRequest.Policies = util.TerraformSetToStringArray(v)
	}

	if v, ok := d.GetOk(consts.FieldTTL); ok {
		createRequest.TTL = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldExplicitMaxTTL); ok {
		createRequest.ExplicitMaxTTL = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldPeriod); ok {
		createRequest.Period = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldNoParent); ok {
		createRequest.NoParent = v.(bool)
	}

	if v, ok := d.GetOk(consts.FieldNoDefaultPolicy); ok {
		createRequest.NoDefaultPolicy = v.(bool)
	}

	if v, ok := d.GetOk(consts.FieldDisplayName); ok {
		createRequest.DisplayName = v.(string)
	}

	if v, ok := d.GetOk(consts.FieldNumUses); ok {
		createRequest.NumUses = v.(int)
	}

	if v, ok := d.GetOkExists(consts.FieldRenewable); ok {
		renewable, ok := v.(bool)
		if !ok {
			return fmt.Errorf("unexpected type %T for %q", d.Get(consts.FieldRenewable), consts.FieldRenewable)
		}
		createRequest.Renewable = &renewable
	}

	if v, ok := d.GetOk(consts.FieldMetadata); ok {
		d := make(map[string]string)
		for k, val := range v.(map[string]interface{}) {
			d[k] = val.(string)
		}
		createRequest.Metadata = d
	}

	if v, ok := d.GetOk(consts.FieldWrappingTTL); ok {
		wrappingTTL := v.(string)

		client, err = client.Clone()
		if err != nil {
			return fmt.Errorf("error cloning client: %w", err)
		}

		client.SetWrappingLookupFunc(func(operation, path string) string {
			return wrappingTTL
		})

		wrapped = true
	}

	var resp *api.Secret
	var accessor string

	if role != "" {
		log.Printf("[DEBUG] Creating token with role %q", role)
		resp, err = client.Auth().Token().CreateWithRole(createRequest, role)
		if err != nil {
			return fmt.Errorf("error creating token with role %q: %s", role, err)
		}

		if wrapped {
			accessor = resp.WrapInfo.WrappedAccessor
		} else {
			accessor = resp.Auth.Accessor
		}

		log.Printf("[DEBUG] Created token accessor %q with role %q", accessor, role)
	} else {
		log.Printf("[DEBUG] Creating token")
		resp, err = client.Auth().Token().Create(createRequest)
		if err != nil {
			return fmt.Errorf("error creating token: %s", err)
		}

		if wrapped {
			accessor = resp.WrapInfo.WrappedAccessor
		} else {
			accessor = resp.Auth.Accessor
		}

		log.Printf("[DEBUG] Created token accessor %q", accessor)
	}

	if wrapped {
		d.Set(consts.FieldWrappedToken, resp.WrapInfo.Token)
		d.Set(consts.FieldWrappingAccessor, resp.WrapInfo.Accessor)
	} else {
		d.Set(consts.FieldClientToken, resp.Auth.ClientToken)
	}

	d.SetId(accessor)

	return tokenRead(d, meta)
}

func tokenRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Get(consts.FieldClientToken).(string)
	accessor := d.Id()

	log.Printf("[DEBUG] Reading token accessor %q", accessor)
	resp, err := client.Auth().Token().LookupAccessor(accessor)
	if err != nil {
		log.Printf("[WARN] Token not found, removing from state")
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Read token accessor %q", accessor)

	iPolicies := resp.Data[consts.FieldPolicies].([]interface{})
	policies := make([]string, 0, len(iPolicies))
	for _, iPolicy := range iPolicies {
		if iPolicy == "default" {
			continue
		}

		policies = append(policies, iPolicy.(string))
	}

	d.Set(consts.FieldPolicies, policies)
	d.Set(consts.FieldNoParent, resp.Data[consts.FieldOrphan])
	d.Set(consts.FieldRenewable, resp.Data[consts.FieldRenewable])
	d.Set(consts.FieldDisplayName, strings.TrimPrefix(resp.Data[consts.FieldDisplayName].(string), "token-"))
	d.Set(consts.FieldNumUses, resp.Data[consts.FieldNumUses])

	issueTimeStr, ok := resp.Data["issue_time"].(string)
	if !ok {
		return fmt.Errorf("error issue_time is not a string, got %T", resp.Data["issue_time"])
	}

	issueTime, err := time.Parse(time.RFC3339Nano, issueTimeStr)
	if err != nil {
		return fmt.Errorf("error parsing issue_time: %s, please format string like '2006-01-02T15:04:05.999999999Z07:00'", err)
	}
	d.Set(consts.FieldLeaseStarted, issueTime.Format(time.RFC3339))

	expireTimeStr, ok := resp.Data["expire_time"].(string)
	if !ok {
		return fmt.Errorf("error expire_time is %T", resp.Data["expire_time"])
	}

	expireTime, err := time.Parse(time.RFC3339Nano, expireTimeStr)
	if err != nil {
		return fmt.Errorf("error parsing expire_time: %s", err)
	}
	d.Set(consts.FieldLeaseDuration, int(expireTime.Sub(issueTime).Seconds()))

	d.Set(consts.FieldMetadata, resp.Data["meta"])

	if d.Get(consts.FieldRenewable).(bool) && tokenCheckLease(d) {
		if id == "" {
			log.Printf("[DEBUG] Lease for token access %q cannot be renewed as it's been encrypted.", accessor)
			return nil
		}

		log.Printf("[DEBUG] Lease for token accessor %q expiring soon, renewing", accessor)

		increment := d.Get(consts.FieldLeaseDuration).(int)

		if v, ok := d.GetOk(consts.FieldRenewIncrement); ok {
			increment = v.(int)
		}

		renewed, err := client.Auth().Token().Renew(id, increment)
		if err != nil {
			log.Printf("[DEBUG] Error renewing token, removing from state")
			d.SetId("")
			return nil
		}

		log.Printf("[DEBUG] Lease for token accessor %q renewed, new lease duration %d", id, renewed.Auth.LeaseDuration)

		d.Set(consts.FieldLeaseDuration, renewed.Data[consts.FieldLeaseDuration])
		d.Set(consts.FieldLeaseStarted, time.Now().Format(time.RFC3339))
		d.Set(consts.FieldClientToken, renewed.Auth.ClientToken)

		d.SetId(renewed.Auth.Accessor)
	}

	return nil
}

func tokenUpdate(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func tokenDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	token := d.Id()

	log.Printf("[DEBUG] Deleting token %q", token)
	err := client.Auth().Token().RevokeAccessor(token)
	if err != nil {
		return fmt.Errorf("error deleting token %q: %s", token, err)
	}
	log.Printf("[DEBUG] Deleted token accessor %q", token)

	return nil
}

func tokenExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	accessor := d.Id()

	log.Printf("[DEBUG] Checking if token accessor %q exists", accessor)
	resp, err := client.Auth().Token().LookupAccessor(accessor)
	if err != nil {
		log.Printf("[DEBUG] token accessor %q not found: %s", d.Id(), err)
		return false, nil
	}
	return resp != nil, nil
}

func tokenCheckLease(d *schema.ResourceData) bool {
	accessor := d.Id()

	startedStr := d.Get(consts.FieldLeaseStarted).(string)
	if startedStr == "" {
		return false
	}

	started, err := time.Parse(time.RFC3339, startedStr)
	if err != nil {
		log.Printf("[DEBUG] lease_started %q for token accessor %q is an invalid value, removing: %s", startedStr, accessor, err)
		d.SetId("")

		return false
	}

	leaseDuration := d.Get(consts.FieldLeaseDuration).(int)

	expireTime := started.Add(time.Second * time.Duration(leaseDuration))
	if expireTime.Before(time.Now()) {
		log.Printf("[DEBUG] token accessor %q has expired", accessor)
		d.SetId("")

		return false
	}

	if v, ok := d.GetOk(consts.FieldRenewMinLease); ok {
		renewMinLease := v.(int)
		if renewMinLease <= 0 {
			return false
		}

		renewTime := int(expireTime.Sub(time.Now()).Seconds())
		if renewTime <= renewMinLease {
			log.Printf("[DEBUG] token accessor %q must be renewed", accessor)

			return true
		}
	}

	return false
}
