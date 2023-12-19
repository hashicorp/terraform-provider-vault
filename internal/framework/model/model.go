package model

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// ToAPIModel is helper to translate Vault response data to its respective
// Vault API data model
func ToAPIModel(data, model any, diagnostics diag.Diagnostics) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		msg := "Unable to marshal Vault response"
		diagnostics.AddError(
			msg,
			"An unexpected error occurred while attempting to marshal the Vault response.\n\n"+
				"Error: "+err.Error(),
		)

		return fmt.Errorf(msg)
	}

	err = json.Unmarshal(jsonData, &model)
	if err != nil {
		msg := "Unable to unmarshal data to API model"
		diagnostics.AddError(
			msg,
			"An unexpected error occurred while attempting to unmarshal the data.\n\n"+
				"Error: "+err.Error(),
		)

		return fmt.Errorf(msg)
	}
	return nil
}
