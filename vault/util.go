package vault

import (
	"encoding/json"
	"log"
	"reflect"

	"github.com/hashicorp/terraform/helper/schema"
)

func jsonDiffSuppress(k, old, new string, d *schema.ResourceData) bool {
	var oldJSON, newJSON interface{}
	err := json.Unmarshal([]byte(old), &oldJSON)
	if err != nil {
		log.Printf("[ERROR] Version of %q in state is not valid JSON: %s", k, err)
		return false
	}
	err = json.Unmarshal([]byte(new), &newJSON)
	if err != nil {
		log.Printf("[ERROR] Version of %q in config is not valid JSON: %s", k, err)
		return true
	}
	return reflect.DeepEqual(oldJSON, newJSON)
}

func toStringArray(input []interface{}) []string {
	output := make([]string, len(input))

	for i, item := range input {
		output[i] = item.(string)
	}

	return output
}
