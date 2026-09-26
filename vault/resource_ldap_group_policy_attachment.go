// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func ldapGroupPolicyAttachmentResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: ldapGroupPolicyAttachmentResourceWrite,
		Update: ldapGroupPolicyAttachmentResourceWrite,
		Read:   provider.ReadWrapper(ldapAuthBackendGroupResourceRead),
		Delete: ldapGroupPolicyAttachmentResourceDelete,
		Exists: ldapAuthBackendUserResourceExists,

		Schema: map[string]*schema.Schema{
			"groupname": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			consts.FieldPolicies: {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Required: true,
			},
			consts.FieldBackend: {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  consts.MountTypeLDAP,
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func ldapGroupPolicyAttachmentResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get(consts.FieldBackend).(string)
	groupname := d.Get("groupname").(string)
	path := ldapAuthBackendGroupResourcePath(backend, groupname)

	resp, err := client.Logical().Read(path)

	if err != nil {
		return fmt.Errorf("error reading ldap group %q: %s", path, err)
	}

	if resp == nil {
		return fmt.Errorf("error: ldap group not found %s", groupname)
	}

	data := map[string]interface{}{}
	if v, ok := d.GetOk(consts.FieldPolicies); ok {
		existingPolicies := []interface{}{}
		if resp.Data != nil {
			if val, ok := resp.Data[consts.FieldPolicies]; ok {
				existingPolicies = val.([]interface{})
			}
		}
		desiredPolicies := v.(*schema.Set).List()
		data[consts.FieldPolicies] = schema.NewSet(schema.HashString, append(existingPolicies, desiredPolicies...)).List()
	}

	log.Printf("[DEBUG] Updating %q", path)
	_, err = client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing ldap group %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote LDAP group %q", path)

	return ldapAuthBackendGroupResourceRead(d, meta)
}

func ldapGroupPolicyAttachmentResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	if v, ok := d.GetOk(consts.FieldPolicies); ok {
		policiesToDelete := v.(*schema.Set).List()

		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading ldap group %q: %s", path, err)
		}

		attachedPolicies := []interface{}{}
		if resp != nil {
			attachedPolicies = resp.Data[consts.FieldPolicies].([]interface{})
		}

		newPolicies := policiesWithout(attachedPolicies, policiesToDelete)

		data := map[string]interface{}{}
		data[consts.FieldPolicies] = schema.NewSet(
			schema.HashString, newPolicies,
		).List()

		log.Printf("[DEBUG] Deleting LDAP group policies %q", path)
		_, err = client.Logical().Write(path, data)
		if err != nil {
			return fmt.Errorf("error deleting policies from ldap group %q", path)
		}
		log.Printf("[DEBUG] Deleted LDAP group policies %q", path)
	}

	return nil
}

func policiesWithout(attachedPolicies []interface{}, policiesToDelete []interface{}) []interface{} {
	newPolicies := []interface{}{}
	for _, policy := range attachedPolicies {
		if !slices.Contains(policiesToDelete, policy) {
			newPolicies = append(newPolicies, policy)
		}
	}
	return newPolicies
}
