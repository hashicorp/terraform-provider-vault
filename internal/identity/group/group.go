// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	LookupPath        = "identity/lookup/group"
	IdentityGroupPath = "/identity/group"

	GroupResourceType = iota
	EntityResourceType
)

func IdentityGroupIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", IdentityGroupPath, id)
}

// ReadIdentityGroup may return `nil` for the IdentityGroup if it does not exist
func ReadIdentityGroup(client *api.Client, groupID string, retry bool) (*api.Secret, error) {
	path := IdentityGroupIDPath(groupID)
	log.Printf("[DEBUG] Reading IdentityGroup %s from %q", groupID, path)

	return entity.ReadEntity(client, path, retry)
}

func IsIdentityNotFoundError(err error) bool {
	return err != nil && errors.Is(err, entity.ErrEntityNotFound)
}

func getFieldFromResourceType(resourceType int) (string, error) {
	var ret string
	switch resourceType {
	case GroupResourceType:
		ret = consts.FieldMemberGroupIDs
	case EntityResourceType:
		ret = consts.FieldMemberEntityIDs
	default:
		return "", fmt.Errorf("unkown resource type")
	}

	return ret, nil
}

// GetGroupMemberUpdateContextFunc is a common context function for all
// Update operations to be performed on Identity Group Members
func GetGroupMemberUpdateContextFunc(resourceType int) func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		gidRaw := d.Get(consts.FieldGroupID)
		gid, ok := gidRaw.(string)
		if !ok {
			return diag.Errorf("invalid Group ID type %T", gidRaw)
		}

		path := IdentityGroupIDPath(gid)
		provider.VaultMutexKV.Lock(path)
		defer provider.VaultMutexKV.Unlock(path)

		client, e := provider.GetClient(d, meta)
		if e != nil {
			return diag.FromErr(e)
		}

		memberField, err := getFieldFromResourceType(resourceType)
		if err != nil {
			return diag.FromErr(err)
		}

		log.Printf("[DEBUG] Updating field %q on Identity Group %q", memberField, gid)

		if d.HasChange(consts.FieldGroupID) {
			o, n := d.GetChange(consts.FieldGroupID)
			log.Printf("[DEBUG] Group ID has changed old=%q, new=%q", o, n)
		}

		resp, err := ReadIdentityGroup(client, gid, d.IsNewResource())
		if err != nil {
			return diag.FromErr(err)
		}

		data, err := GetGroupMember(d, resp, memberField)
		if err != nil {
			return diag.FromErr(err)
		}

		_, err = client.Logical().Write(path, data)
		if err != nil {
			return diag.Errorf("error updating field %q on Identity Group %s: err=%s", memberField, gid, err)
		}
		log.Printf("[DEBUG] Updated field %q on Identity Group %s", memberField, gid)

		d.SetId(gid)

		return nil
	}
}

// GetGroupMemberReadContextFunc is a common context function for all
// read operations to be performed on Identity Group Members
func GetGroupMemberReadContextFunc(resourceType int, setGroupName bool) schema.ReadContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		client, e := provider.GetClient(d, meta)
		if e != nil {
			return diag.FromErr(e)
		}

		id := d.Id()

		memberField, err := getFieldFromResourceType(resourceType)
		if err != nil {
			return diag.FromErr(err)
		}

		log.Printf("[DEBUG] Reading Identity Group %s with field %q", id, memberField)
		resp, err := ReadIdentityGroup(client, id, d.IsNewResource())
		if err != nil {
			if IsIdentityNotFoundError(err) {
				log.Printf("[WARN] Identity Group %s not found, removing from state", id)
				d.SetId("")
				return nil
			}
			return diag.FromErr(err)
		}

		if err := d.Set(consts.FieldGroupID, id); err != nil {
			return diag.FromErr(err)
		}

		if setGroupName {
			if err := d.Set(consts.FieldGroupName, resp.Data[consts.FieldName]); err != nil {
				return diag.FromErr(err)
			}
		}

		if err := SetGroupMember(d, resp, memberField); err != nil {
			return diag.FromErr(err)
		}

		return nil
	}
}

// GetGroupMemberDeleteContextFunc is a common context function for all
// delete operations to be performed on Identity Group Members
func GetGroupMemberDeleteContextFunc(resourceType int) schema.DeleteContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		idRaw := d.Get(consts.FieldGroupID)
		id, ok := idRaw.(string)
		if !ok {
			return diag.Errorf("invalid Group ID type %T", idRaw)
		}

		path := IdentityGroupIDPath(id)
		provider.VaultMutexKV.Lock(path)
		defer provider.VaultMutexKV.Unlock(path)

		client, e := provider.GetClient(d, meta)
		if e != nil {
			return diag.FromErr(e)
		}

		memberField, err := getFieldFromResourceType(resourceType)
		if err != nil {
			return diag.FromErr(err)
		}

		log.Printf("[DEBUG] Deleting Identity Group %q with field %q", memberField, id)

		resp, err := ReadIdentityGroup(client, id, false)
		if err != nil {
			if IsIdentityNotFoundError(err) {
				return nil
			}
			return diag.FromErr(err)
		}

		data, err := DeleteGroupMember(d, resp, memberField)
		if err != nil {
			return diag.FromErr(err)
		}

		_, err = client.Logical().Write(path, data)
		if err != nil {
			return diag.Errorf("error deleting Identity Group %q with field %q; err=%s", id, memberField, err)
		}
		log.Printf("[DEBUG]  Deleted Identity Group %q with field %q", memberField, id)

		return nil
	}
}

// GetGroupMember returns group member data based on an input
// 'memberField'. It manages the lifecycle of internal group
// members appropriately by performing any necessary deduplication
func GetGroupMember(d *schema.ResourceData, resp *api.Secret, memberField string) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	switch memberField {
	case consts.FieldMemberGroupIDs, consts.FieldMemberEntityIDs:
	default:
		return nil, fmt.Errorf("invalid value for member field")
	}
	var curIDS []interface{}
	if t, ok := resp.Data[consts.FieldType]; ok && t.(string) != consts.FieldExternal {
		if v, ok := resp.Data[memberField]; ok && v != nil {
			curIDS = v.([]interface{})
		}

		if d.Get(consts.FieldExclusive).(bool) || len(curIDS) == 0 {
			data[memberField] = d.Get(memberField).(*schema.Set).List()
		} else {
			set := map[interface{}]bool{}
			for _, v := range curIDS {
				set[v] = true
			}

			o, _ := d.GetChange(memberField)
			if !d.IsNewResource() && o != nil {
				// set.delete()
				for _, i := range o.(*schema.Set).List() {
					delete(set, i)
				}
			}

			if ids, ok := d.GetOk(memberField); ok {
				for _, id := range ids.(*schema.Set).List() {
					// set.add()
					set[id] = true
				}
			}

			// set.keys()
			var result []interface{}
			for k := range set {
				result = append(result, k)
			}
			data[memberField] = result
		}
	}

	return data, nil
}

// SetGroupMember sets group member data to the TF state based
// on a 'memberField'
func SetGroupMember(d *schema.ResourceData, resp *api.Secret, memberField string) error {
	curIDS := resp.Data[memberField]
	if d.Get(consts.FieldExclusive).(bool) {
		if err := d.Set(memberField, curIDS); err != nil {
			return err
		}
	} else {
		set := map[interface{}]bool{}
		if curIDS != nil {
			for _, v := range curIDS.([]interface{}) {
				set[v] = true
			}
		}

		var result []interface{}
		// set.intersection()
		if i, ok := d.GetOk(memberField); ok && i != nil {
			for _, v := range i.(*schema.Set).List() {
				if _, ok := set[v]; ok {
					result = append(result, v)
				}
			}
		}
		if err := d.Set(memberField, result); err != nil {
			return err
		}
	}

	return nil
}

// DeleteGroupMember deletes group member data from Vault and the TF
// state based on a 'memberField'
func DeleteGroupMember(d *schema.ResourceData, resp *api.Secret, memberField string) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	switch memberField {
	case consts.FieldMemberGroupIDs, consts.FieldMemberEntityIDs:
	default:
		return nil, fmt.Errorf("invalid value for member field")
	}

	t, ok := resp.Data[consts.FieldType]
	if ok && t != consts.FieldExternal {
		if d.Get(consts.FieldExclusive).(bool) {
			data[memberField] = make([]string, 0)
		} else {
			set := map[interface{}]bool{}
			if v, ok := resp.Data[memberField]; ok && v != nil {
				for _, id := range v.([]interface{}) {
					set[id] = true
				}
			}

			result := []interface{}{}
			if len(set) > 0 {
				if v, ok := d.GetOk(memberField); ok {
					for _, id := range v.(*schema.Set).List() {
						delete(set, id)
					}
				}

				for k := range set {
					result = append(result, k)
				}
			}
			data[memberField] = result
		}
	}

	return data, nil
}
