// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"testing"
)

const testSSHKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDR6q4PTcuIkpdGEqaCaxnR8/REqlbSiEIKaRZkVSjiTXOaiSfUsy9cY2+7+oO9fLMUrhylImerjzEoagX1IjYvc9IeUBaRnfacN7QwUDfstgp2jknbg7rNX9j9nFxwltV/jYQPcRq8Ud0wn1nb4qixq+diM7+Up+xJOeaKxbpjEUJH5dcvaBB+Aa24tJpjOQxtFyQ6dUxlgJu0tcygZR92kKYCVjZDohlSED3i/Ak2KFwqCKx2IZWq9z1vMEgmRzv++4Qt1OsbpW8itiCyWn6lmV33eDCdjMrr9TEThQNnMinPrHdmVUnPZ/OomP+rLDRE9lQR16uaSvKhg5TWOFIXRPyEhX9arEATrE4KSWeQN2qgHOb6P24YqgEm1ZdHJq25q/nBBAa1x0tFMiWqZwOsGeJ9nTeOeyiqFKH5YRBo6DIy3ag3taFsfQSve6oqjnrudUd1hJ8/bNSz8amECfP0ULvAEAgpiurj3eCPc3OcXl4tAld9F6KwabEJV5eelcs= user@example.com"

func TestDataSourceSSHSecretBackendSign(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceSSHSecretBackendSign_config,
				Check:  testDataSourceSSHSecretBackendSign_check,
			},
		},
	})
}

var testDataSourceSSHSecretBackendSign_config = `
resource "vault_mount" "test" {
  path        = "ssh-test"
  type        = "ssh"
  description = "This is an example mount"
}

resource "vault_ssh_secret_backend_ca" "test" {
  backend 		       = vault_mount.test.path
  key_bits             = 4096
  generate_signing_key = true
}

resource "vault_ssh_secret_backend_role" "test" {
    backend                 = vault_mount.test.path
    key_type                = "ca"
    name                    = "test"
    algorithm_signer        = "rsa-sha2-256"
    allow_user_certificates = true
    allowed_users           = "*"
    allowed_extensions      = "permit-pty,permit-port-forwarding"
    default_extensions      = {
    	permit-pty = ""
    }
    default_user            = "ubuntu"
    ttl                     = "30m0s"
}

data "vault_ssh_secret_backend_sign" "test" {
    path             = vault_mount.test.path
    public_key       = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDR6q4PTcuIkpdGEqaCaxnR8/REqlbSiEIKaRZkVSjiTXOaiSfUsy9cY2+7+oO9fLMUrhylImerjzEoagX1IjYvc9IeUBaRnfacN7QwUDfstgp2jknbg7rNX9j9nFxwltV/jYQPcRq8Ud0wn1nb4qixq+diM7+Up+xJOeaKxbpjEUJH5dcvaBB+Aa24tJpjOQxtFyQ6dUxlgJu0tcygZR92kKYCVjZDohlSED3i/Ak2KFwqCKx2IZWq9z1vMEgmRzv++4Qt1OsbpW8itiCyWn6lmV33eDCdjMrr9TEThQNnMinPrHdmVUnPZ/OomP+rLDRE9lQR16uaSvKhg5TWOFIXRPyEhX9arEATrE4KSWeQN2qgHOb6P24YqgEm1ZdHJq25q/nBBAa1x0tFMiWqZwOsGeJ9nTeOeyiqFKH5YRBo6DIy3ag3taFsfQSve6oqjnrudUd1hJ8/bNSz8amECfP0ULvAEAgpiurj3eCPc3OcXl4tAld9F6KwabEJV5eelcs= user@example.com"
    name             = "test"
    valid_principals = "my-user"
}
`

func testDataSourceSSHSecretBackendSign_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_ssh_secret_backend_sign.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if serialNumber := iState.Attributes["serial_number"]; serialNumber == "" {
		return errors.New("got empty string for serial_number")
	}

	signedKey := iState.Attributes["signed_key"]
	if signedKey == "" {
		return errors.New("got empty string for signed_key")
	}

	resourceState = s.Modules[0].Resources["data.vault_ssh_secret_backend_ca.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState = resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	caPublicKey := iState.Attributes["public_key"]
	if caPublicKey == "" {
		return errors.New("got empty string for public_key")
	}

	return nil
}
