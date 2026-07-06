// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// pkiCertPlanAutoRenewal proposes automatic renewal during planning (if enabled)
// because the Create and Read functions will both set renew_pending if
// the current time is after the min_seconds_remaining timestamp.
func pkiCertPlanAutoRenewal(d *schema.ResourceDiff) error {
	if d.Id() == "" || !d.Get(consts.FieldAutoRenew).(bool) {
		return nil
	}
	if d.Get(consts.FieldRenewPending).(bool) {
		log.Printf("[DEBUG] certificate %q is due for renewal", d.Id())
		if err := d.SetNewComputed(consts.FieldCertificate); err != nil {
			return err
		}

		if err := d.ForceNew(consts.FieldCertificate); err != nil {
			return err
		}

		// Renewing the certificate will reset the value of renew_pending
		d.SetNewComputed(consts.FieldRenewPending)
		if err := d.ForceNew(consts.FieldRenewPending); err != nil {
			return err
		}

		return nil
	}

	log.Printf("[DEBUG] certificate %q is not due for renewal", d.Id())
	return nil
}
