# Copyright IBM Corp. 2016, 2026
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
				// GO-2026-5932 flags the golang.org/x/crypto/openpgp subpackage as unmaintained/unsafe.
				// TFVP does not import or call openpgp anywhere; confirmed via `go mod why` (package not
				// needed by the main module) and `govulncheck -mode=binary`, which found the symbol
				// unreachable in the built binary. False positive from module-level (non-symbol) matching.
				"GO-2026-5932"
			]
		}
	}
}
