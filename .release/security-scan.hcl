# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
#
# Reference: https://github.com/hashicorp/security-scanner/blob/main/CONFIG.md#binary (private repository)

binary {
  secrets {
    all = true
  }
  go_modules   = true
  osv          = true
  oss_index    = false
  nvd          = false

	triage {
		suppress {
			vulnerabilities = [
				// GO-2022-0635 is of low severity, and VSO isn't using the affected functionalities
				// Upgrading to latest version of go-secure-stdlib is not possible at this time.
				// The required functionality was inadvertently dropped from
				// github.com/hashicorp/go-secure-stdlib/awsutil during the migration to aws-sdk-go-v2.
				"GO-2022-0635",
				// This is a false positive that has been fixed as of
				// github.com/jackc/pgx/v5 @ >= v5.0.9
				// There is a open request to have the vulndb updated as such:
				// https://github.com/golang/vulndb/issues/4943
				"GO-2026-4771",
			]
		}
	}
}
