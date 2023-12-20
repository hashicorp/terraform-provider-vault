package model

import (
	"encoding/json"
	"fmt"
)

// ToAPIModel is helper to translate Vault response data to its respective
// Vault API data model
func ToAPIModel(data, model any) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf(
			"An unexpected error occurred while attempting to marshal the Vault response.\n\n" +
				"Error: " + err.Error(),
		)
	}

	err = json.Unmarshal(jsonData, &model)
	if err != nil {
		return fmt.Errorf(
			"An unexpected error occurred while attempting to unmarshal the data.\n\n" +
				"Error: " + err.Error(),
		)
	}
	return nil
}
