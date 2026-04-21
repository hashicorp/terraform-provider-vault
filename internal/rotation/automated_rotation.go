// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package automatedrotationutil

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/vault/api"
)

var AutomatedRotationFields = []string{
	consts.FieldRotationSchedule,
	consts.FieldRotationPeriod,
	consts.FieldRotationWindow,
	consts.FieldDisableAutomatedRotation,
}

var AutomatedRotationFieldsWithPolicy = append(
	AutomatedRotationFields,
	consts.FieldRotationPolicy)

func ParseAutomatedRotationFields(d *schema.ResourceData, data map[string]interface{}) {
	for _, field := range AutomatedRotationFields {
		data[field] = d.Get(field)
	}
}

func PopulateAutomatedRotationFields(d *schema.ResourceData, resp *api.Secret, path string) error {
	for _, k := range AutomatedRotationFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for mount at %q: %q", k, path, err)
			}
		}
	}

	return nil
}

// PopulateAutomatedRotationFieldsWithPolicy is meant to be used by plugins onboarded onto
// the rotation policy mechanism. The caller of this function should ensure the Vault API version
// is >= Vault Enterprise 2.0
func PopulateAutomatedRotationFieldsWithPolicy(d *schema.ResourceData, resp *api.Secret, path string) error {
	for _, k := range AutomatedRotationFieldsWithPolicy {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for mount at %q: %q", k, path, err)
			}
		}
	}

	return nil
}

func ParseAutomatedRotationFieldsWithFieldPrefix(d *schema.ResourceData, data map[string]interface{}, prefix string) {
	for _, field := range AutomatedRotationFields {
		data[field] = d.Get(prefix + field)
	}
}

// ParseAutomatedRotationFieldsWithPolicy is meant to be used by plugins onboarded onto
// the rotation policy mechanism. The caller of this function should ensure the Vault API version
// is >= Vault Enterprise 2.0
func ParseAutomatedRotationFieldsWithPolicy(d *schema.ResourceData, data map[string]interface{}) {
	for _, field := range AutomatedRotationFieldsWithPolicy {
		data[field] = d.Get(field)
	}
}

func GetAutomatedRotationFieldsFromResponse(resp *api.Secret, result map[string]interface{}) {
	for _, k := range AutomatedRotationFields {
		if v, ok := resp.Data[k]; ok {
			result[k] = v
		}
	}
}
