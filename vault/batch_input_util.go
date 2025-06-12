package vault

import (
	"fmt"
	"maps"
	"strconv"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var intFields = []string{
	consts.FieldMACLength,
	consts.FieldKeyVersion,
}

// When batch_input is provided as a map, all of the fields get parsed as strings,
// which results in an error if non-string parameters are included, because Vault
// expects a different type. convertBatchInput converts these values to their correct
// types to avoid this error
func convertBatchInput(batchInput interface{}) ([]map[string]interface{}, error) {
	convertedBatchInput := make([]map[string]interface{}, 0)

	inputList, ok := batchInput.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected batch_input to be a slice, got %T", batchInput)
	}

	for _, input := range inputList {
		inputMap, ok := input.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("expected batch_input element to be a map, got %T", input)
		}

		mapCopy := make(map[string]interface{})
		maps.Copy(mapCopy, inputMap)

		for _, key := range intFields {
			if f, ok := mapCopy[key]; ok {
				intField, err := strconv.Atoi(f.(string))
				if err != nil {
					return nil, fmt.Errorf("error converting field %s to int: %s", key, err)
				}

				mapCopy[key] = intField
			}
		}

		convertedBatchInput = append(convertedBatchInput, mapCopy)
	}

	return convertedBatchInput, nil
}

// The code that does the parsing for maps will panic if given a map with a mix of boolean
// and string values. This function converts booleans to strings to avoid the error.
func convertBatchResults(rawResults interface{}) ([]map[string]interface{}, error) {
	batchResultsList, ok := rawResults.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected batch_results type %T", rawResults)
	}

	var batchResults []map[string]interface{}
	for _, result := range batchResultsList {
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected element type %T", result)
		}

		mapCopy := make(map[string]interface{})
		maps.Copy(mapCopy, resultMap)

		stringMap := make(map[string]interface{})
		for k, v := range mapCopy {
			switch v.(type) {
			case bool:
				stringMap[k] = strconv.FormatBool(v.(bool))
			default:
				stringMap[k] = v
			}
		}

		batchResults = append(batchResults, stringMap)
	}

	return batchResults, nil
}
