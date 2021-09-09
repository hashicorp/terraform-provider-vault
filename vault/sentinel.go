package vault

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"log"
)

func readSentinelPolicy(client *api.Client, policyType string, name string) (map[string]interface{}, error) {
	r := client.NewRequest("GET", fmt.Sprintf("/v1/sys/policies/%s/%s", policyType, name))

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := client.RawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("data from server response is empty")
	}
	return secret.Data, nil
}

func PutSentinelPolicy(client *api.Client, policyType string, name string, body map[string]interface{}) error {
	r := client.NewRequest("PUT", fmt.Sprintf("/v1/sys/policies/%s/%s", policyType, name))
	if err := r.SetJSONBody(body); err != nil {
		return err
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := client.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func DeleteSentinelPolicy(client *api.Client, policyType string, name string) error {
	r := client.NewRequest("DELETE", fmt.Sprintf("/v1/sys/policies/%s/%s", policyType, name))

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := client.RawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

func ValidateSentinelEnforcementLevel(v interface{}, k string) (ws []string, errs []error) {
	value := v.(string)
	if value != "advisory" && value != "soft-mandatory" && value != "hard-mandatory" {
		errs = append(errs, fmt.Errorf("unexpected value %s", value))
	}
	return
}

func sentinelPolicyDelete(policyType string, d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Id()

	log.Printf("[DEBUG] Deleting %s policy %s from Vault", policyType, name)

	err := DeleteSentinelPolicy(client, policyType, name)
	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func sentinelPolicyRead(policyType string, attributes []string, d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Id()

	policy, err := readSentinelPolicy(client, policyType, name)

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	for _, value := range attributes {
		d.Set(value, policy[value])
	}
	d.Set("name", name)

	return nil
}

func sentinelPolicyWrite(policyType string, attributes []string, d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	log.Printf("[DEBUG] Writing %s policy %s to Vault", policyType, name)
	body := map[string]interface{}{}
	for _, value := range attributes {
		body[value] = d.Get(value)
	}

	err := PutSentinelPolicy(client, policyType, name, body)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(name)

	return sentinelPolicyRead(policyType, attributes, d, meta)
}
