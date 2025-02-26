// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package automatedrotationutil

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
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

func ParseAutomatedRotationFields(d *schema.ResourceData, data map[string]interface{}) {
	for _, field := range AutomatedRotationFields {
		data[field] = d.Get(field)
	}
}

func PopulateAutomatedRotationFields(d *schema.ResourceData, resp *api.Secret, path string) diag.Diagnostics {
	for _, k := range AutomatedRotationFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error reading %s for AWS Secret Backend %q: %q", k, path, err)
			}
		}
	}

	return nil
}
