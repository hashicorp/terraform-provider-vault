package vault

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func readPasswordPolicy(client *util.Client, name string) (map[string]interface{}, error) {
	r, err := client.NewRequest("GET", fmt.Sprintf("/v1/sys/policies/password/%s", name))
	if err != nil {
		return nil, fmt.Errorf("error creating new request: %w", err)
	}

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

func passwordPolicyDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*util.Client)

	name := d.Id()

	log.Printf("[DEBUG] Deleting %s password policy from Vault", name)

	r, err := client.NewRequest("DELETE", fmt.Sprintf("/v1/sys/policies/password/%s", name))
	if err != nil {
		return fmt.Errorf("error creating new request: %w", err)

	}
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := client.RawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}

	return err
}

func passwordPolicyRead(attributes []string, d *schema.ResourceData, meta interface{}) error {
	client := meta.(*util.Client)

	name := d.Id()

	policy, err := readPasswordPolicy(client, name)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	for _, value := range attributes {
		d.Set(value, policy[value])
	}
	d.Set("name", name)

	return nil
}

func passwordPolicyWrite(attributes []string, d *schema.ResourceData, meta interface{}) error {
	client := meta.(*util.Client)

	name := d.Get("name").(string)

	log.Printf("[DEBUG] Writing %s password policy to Vault", name)

	body := map[string]interface{}{}
	for _, value := range attributes {
		body[value] = d.Get(value)
	}

	r, err := client.NewRequest("PUT", fmt.Sprintf("/v1/sys/policies/password/%s", name))
	if err != nil {
		return fmt.Errorf("error creating new request: %w", err)
	}

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

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(name)

	return passwordPolicyRead(attributes, d, meta)
}
