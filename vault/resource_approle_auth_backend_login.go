// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func approleAuthBackendLoginResource() *schema.Resource {
	return &schema.Resource{
		Create: approleAuthBackendLoginCreate,
		Read:   provider.ReadWrapper(approleAuthBackendLoginRead),
		Delete: approleAuthBackendLoginDelete,
		Exists: approleAuthBackendLoginExists,

		Schema: map[string]*schema.Schema{
			consts.FieldRoleID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The RoleID to log in with.",
				ForceNew:    true,
			},
			consts.FieldSecretID: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The SecretID to log in with. Required unless `bind_secret_id` is set to false on the role.",
				ForceNew:      true,
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldSecretIDWO},
			},
			consts.FieldSecretIDWO: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The SecretID to log in with. Write-only attribute that can accept ephemeral values." +
					" Required unless `bind_secret_id` is set to false on the role.",
				WriteOnly:     true,
				Sensitive:     true,
				ConflictsWith: []string{consts.FieldSecretID},
			},
			consts.FieldSecretIDWOVersion: {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "Version counter for the write-only secret_id field. " +
					"Increment this to trigger re-authentication with a new SecretID.",
				ForceNew: true,
			},
			consts.FieldPolicies: {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies set on the token.",
			},
			consts.FieldRenewable: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the token is renewable or not.",
			},
			consts.FieldLeaseDuration: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "How long the token is valid for.",
			},
			consts.FieldLeaseStarted: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The timestamp the lease started on, as determined by the machine running Terraform.",
			},
			consts.FieldAccessor: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor for the token.",
			},
			consts.FieldClientToken: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The token.",
				Sensitive:   true,
			},
			consts.FieldMetadata: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Metadata associated with the token.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "approle",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func approleAuthBackendLoginCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get(consts.FieldBackend).(string)

	path := approleAuthBackendLoginPath(backend)

	log.Printf("[DEBUG] Logging in with AppRole auth backend %q", path)
	data := map[string]interface{}{
		consts.FieldRoleID: d.Get(consts.FieldRoleID).(string),
	}

	// Check for WriteOnly field first (ephemeral support)
	if rawVal, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldSecretIDWO)); !rawVal.IsNull() {
		data[consts.FieldSecretID] = rawVal.AsString()
	} else if v, ok := d.GetOk(consts.FieldSecretID); ok {
		data[consts.FieldSecretID] = v.(string)
	}

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error logging into AppRole auth backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Logged in with AppRole auth backend %q", path)

	d.SetId(resp.Auth.Accessor)
	d.Set(consts.FieldLeaseStarted, time.Now().Format(time.RFC3339))
	d.Set(consts.FieldClientToken, resp.Auth.ClientToken)

	return approleAuthBackendLoginRead(d, meta)
}

func approleAuthBackendLoginRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	log.Printf("[DEBUG] Reading token %q", d.Id())
	resp, err := client.Auth().Token().LookupAccessor(d.Id())
	if err != nil {
		// If the token is not found (it has expired) we don't return an error
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading token %q from Vault: %s", d.Id(), err)
	}
	if resp == nil {
		log.Printf("[DEBUG] Token %q not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Read token %q", d.Id())
	if leaseExpiringSoon(d, client) {
		log.Printf("[DEBUG] Lease for %q expiring soon, renewing", d.Id())
		renewed, err := client.Auth().Token().Renew(d.Get(consts.FieldClientToken).(string), d.Get(consts.FieldLeaseDuration).(int))
		if err != nil {
			log.Printf("[DEBUG] Error renewing token %q, bailing", d.Id())
		} else {
			resp = renewed
			d.Set(consts.FieldLeaseStarted, time.Now().Format(time.RFC3339))
			d.Set(consts.FieldClientToken, resp.Auth.ClientToken)
			d.SetId(resp.Auth.Accessor)
		}
	}

	d.Set(consts.FieldPolicies, resp.Data[consts.FieldPolicies])
	d.Set(consts.FieldRenewable, resp.Data[consts.FieldRenewable])
	d.Set(consts.FieldLeaseDuration, resp.Data[consts.FieldLeaseDuration])
	d.Set(consts.FieldMetadata, resp.Data[consts.FieldMetadata])
	d.Set(consts.FieldAccessor, resp.Data[consts.FieldAccessor])
	return nil
}

func approleAuthBackendLoginDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	accessor := d.Id()

	log.Printf("[DEBUG] Revoking token %q", accessor)
	err := client.Auth().Token().RevokeAccessor(accessor)
	if err != nil {
		return fmt.Errorf("error revoking token %q", accessor)
	}
	log.Printf("[DEBUG] Revoked token %q", accessor)

	return nil
}

func approleAuthBackendLoginExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	accessor := d.Id()

	log.Printf("[DEBUG] Checking if token %q exists", accessor)
	resp, err := client.Auth().Token().LookupAccessor(accessor)
	if err != nil {
		// If the token is not found (it has expired) we don't return an error
		if util.IsExpiredTokenErr(err) {
			return false, nil
		}
		return true, fmt.Errorf("error reading %q: %s", accessor, err)
	}
	return resp != nil, nil
}

func approleAuthBackendLoginPath(backend string) string {
	return "auth/" + strings.Trim(backend, "/") + "/login"
}

func leaseExpiringSoon(d *schema.ResourceData, client *api.Client) bool {
	startedStr := d.Get(consts.FieldLeaseStarted).(string)
	duration := d.Get(consts.FieldLeaseDuration).(int)
	if startedStr == "" {
		return false
	}
	started, err := time.Parse(time.RFC3339, startedStr)
	if err != nil {
		log.Printf("[DEBUG] lease_started %q for %q is an invalid value, removing: %s", startedStr, d.Id(), err)
		d.Set(consts.FieldLeaseStarted, "")
		return false
	}
	// whether the time the lease started plus the number of seconds specified in the duration
	// plus five minutes of buffer is before the current time or not. If it is, we don't need to
	// renew just yet.
	if started.Add(time.Second * time.Duration(duration)).Add(time.Minute * 5).Before(time.Now()) {
		return false
	}
	// if the lease duration expired more than five minutes ago, we can't renew anyways, so don't
	// bother even trying.
	if started.Add(time.Second * time.Duration(duration)).After(time.Now().Add(time.Minute * -5)) {
		return false
	}

	// the lease will expire in the next five minutes, or expired less than five minutes ago, in
	// which case renewing is worth a shot
	return true
}
