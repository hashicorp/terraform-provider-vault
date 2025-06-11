// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func transitCMACDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(transitCMACDataSourceRead),

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the key belongs to.",
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the CMAC key to use.",
			},
			consts.FieldKeyVersion: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The version of the key to use",
			},
			consts.FieldInput: {
				Type:         schema.TypeString,
				Optional:     true,
				AtLeastOneOf: []string{consts.FieldInput, consts.FieldBatchInput},
				Description:  "Specifies the base64 encoded input data. One of input or batch_input must be supplied.",
			},
			consts.FieldMACLength: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Specifies the MAC length to use (POST body parameter). The mac_length cannot be larger than the cipher's block size.",
			},
			consts.FieldURLMACLength: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Specifies the MAC length to use (URL parameter). If provided, this value overrides mac_length. The url_mac_length cannot be larger than the cipher's block size.",
			},
			consts.FieldBatchInput: {
				Type:         schema.TypeList,
				Optional:     true,
				AtLeastOneOf: []string{consts.FieldInput, consts.FieldBatchInput},
				Description:  "Specifies a list of items for processing. When this parameter is set, any supplied 'input' or 'context' parameters will be ignored. Responses are returned in the 'batch_results' array component of the 'data' element of the response. Any batch output will preserve the order of the batch input. If the input data value of an item is invalid, the corresponding item in the 'batch_results' will have the key 'error' with a value describing the error.",
				Elem:         &schema.Schema{Type: schema.TypeMap},
			},
			consts.FieldCMAC: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The CMAC returned from Vault if using input",
			},
			consts.FieldBatchResults: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "The results returned from Vault if using batch_input",
				Elem:        &schema.Schema{Type: schema.TypeMap},
			},
		},
	}
}

func transitCMACDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Get(consts.FieldPath).(string)
	keyName := d.Get(consts.FieldName).(string)

	payload := map[string]interface{}{}

	if batchInput, ok := d.GetOk(consts.FieldBatchInput); ok {
		payload[consts.FieldBatchInput], err = convertBatchInput(batchInput)
		if err != nil {
			return err
		}
	} else {
		cmacAPIFields := []string{
			consts.FieldKeyVersion,
			consts.FieldInput,
			consts.FieldMACLength,
		}

		for _, f := range cmacAPIFields {
			if v, ok := d.GetOk(f); ok {
				payload[f] = v
			}
		}
	}

	var reqPath string
	if urlMACLength, ok := d.GetOk(consts.FieldURLMACLength); ok {
		reqPath = fmt.Sprintf("%s/cmac/%s/%d", path, keyName, urlMACLength)
	} else {
		reqPath = fmt.Sprintf("%s/cmac/%s", path, keyName)
	}
	resp, err := client.Logical().Write(reqPath, payload)
	if err != nil {
		return fmt.Errorf("error generating CMAC with key: %s", err)
	}

	d.SetId(reqPath)

	batchResults, batchOK := resp.Data[consts.FieldBatchResults]
	cmac, cmacOK := resp.Data[consts.FieldCMAC]

	if batchOK {
		err = d.Set(consts.FieldBatchResults, batchResults)
		if err != nil {
			return err
		}
	} else if cmacOK {
		err = d.Set(consts.FieldCMAC, cmac)
		if err != nil {
			return err
		}
	} else {
		return errors.New("response contained neither batch_results field nor CMAC field")
	}

	return nil
}

// when batch_input is provided as a map, all of the fields get parsed as strings,
// which results in an error if mac_length is included, because Vault expects an int.
// convertBatchInput converts these values to integers to avoid this error
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

		if macLength, ok := inputMap[consts.FieldMACLength]; ok {
			intMacLength, err := strconv.Atoi(macLength.(string))
			if err != nil {
				return nil, fmt.Errorf("error converting mac_length to int: %s", err)
			}

			inputMap[consts.FieldMACLength] = intMacLength
		}
		if keyVersion, ok := inputMap[consts.FieldKeyVersion]; ok {
			intKeyVersion, err := strconv.Atoi(keyVersion.(string))
			if err != nil {
				return nil, fmt.Errorf("error converting key_version to int: %s", err)
			}

			inputMap[consts.FieldKeyVersion] = intKeyVersion
		}

		convertedBatchInput = append(convertedBatchInput, inputMap)
	}

	return convertedBatchInput, nil
}
