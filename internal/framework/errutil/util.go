// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package errutil

const (
	unexpectedErr = "An unexpected error occurred while attempting to read the resource. " +
		"Please retry the operation or report this issue to the provider developers.\n\n"
)

func ClientConfigureErr(err error) (string, string) {
	return "Error Configuring Resource Client", err.Error()
}

func VaultCreateErr(err error) (string, string) {
	return "Unable to Create Resource",
		unexpectedErr +
			"HTTP Error: " + err.Error()
}

func VaultReadErr(err error) (string, string) {
	return "Unable to Read Resource from Vault",
		unexpectedErr +
			"HTTP Error: " + err.Error()
}

func VaultUpdateErr(err error) (string, string) {
	return "Unable to Update Resource",
		unexpectedErr +
			"HTTP Error: " + err.Error()
}

func VaultDeleteErr(err error) (string, string) {
	return "Unable to Delete Resource",
		unexpectedErr +
			"HTTP Error: " + err.Error()
}

func VaultReadResponseNil() (string, string) {
	return "Unable to Read Resource from Vault",
		unexpectedErr +
			"Vault response was nil"
}
