// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package helper

import (
	"encoding/json"
	"time"

	"github.com/hashicorp/terraform-provider-vault/util"
)

// FlattenVaultDuration converts a Vault TypeDurationSecond value (integer seconds)
// to a short-form duration string (e.g. "8760h"). Returns "" for zero or nil —
// 0 is the zero-value for this type and indicates "unset".
func FlattenVaultDuration(d interface{}) string {
	if d == nil {
		return ""
	}

	var secs int64
	switch v := d.(type) {
	case int:
		secs = int64(v)
	case int64:
		secs = v
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return ""
		}
		secs = i
	default:
		return ""
	}

	if secs == 0 {
		return ""
	}
	return util.ShortDur(time.Duration(secs) * time.Second)
}
