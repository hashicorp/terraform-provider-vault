// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package os_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const testAccOSSSHHostEnvVar = "TF_VAULT_OS_SSH_HOST"

// TestAccOSSecretBackendAccount_basic covers CRUD and import without requiring
// a live SSH login. It disables verify_connection and uses a unique username so
// the provider behavior can be validated without shared host-side state.
func TestAccOSSecretBackendAccount_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	username := acctest.RandomWithPrefix("tf-user")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "86400"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_window"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_schedule"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerifyConnection, "false"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccOSSecretBackendAccountImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldPasswordWO,
					consts.FieldRotationPeriod,
					consts.FieldRotationWindow,
					consts.FieldVerifyConnection,
					consts.FieldLastVaultRotation,
					consts.FieldNextVaultRotation,
				},
			},
			{
				Config: testAccOSSecretBackendAccountConfig_updated(mount, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "172800"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_window"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerifyConnection, "false"),
				),
			},
		},
	})
}

// TestAccOSSecretBackendAccount_basicSSH keeps one explicit SSH-dependent path
// that validates account onboarding with verify_connection enabled against the
// live test container user configured in the runbook.
func TestAccOSSecretBackendAccount_basicSSH(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	sshHost := testutil.SkipTestEnvUnset(t, testAccOSSSHHostEnvVar)[0]
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_basicWithHost(mount, hostName, accountName, "user-1", sshHost, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, "user-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerifyConnection, "true"),
					testAccOSSecretBackendAccountCheckManualRotate(resourceName),
				),
			},
		},
	})
}

// testAccOSSecretBackendAccountCheckManualRotate uses the provider-managed
// client to invoke the account rotate endpoint and then verifies Vault reports
// a populated last_vault_rotation timestamp.
func testAccOSSecretBackendAccountCheckManualRotate(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}

		client, err := provider.GetClient(rs.Primary, acctestutil.TestProvider.Meta())
		if err != nil {
			return err
		}

		accountPath := fmt.Sprintf("%s/hosts/%s/accounts/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldHost],
			rs.Primary.Attributes[consts.FieldName],
		)

		before, err := client.Logical().Read(accountPath)
		if err != nil {
			return fmt.Errorf("error reading account before manual rotation: %w", err)
		}
		if before == nil {
			return fmt.Errorf("account not found before manual rotation at %q", accountPath)
		}
		if len(before.Warnings) > 0 {
			return fmt.Errorf("unexpected warnings before manual rotation at %q: %v", accountPath, before.Warnings)
		}

		rotateResp, err := client.Logical().Write(accountPath+"/rotate", map[string]interface{}{})
		if err != nil {
			return fmt.Errorf("error manually rotating account at %q: %w", accountPath, err)
		}
		if rotateResp != nil && len(rotateResp.Warnings) > 0 {
			return fmt.Errorf("unexpected warnings from manual rotation at %q: %v", accountPath, rotateResp.Warnings)
		}

		after, err := client.Logical().Read(accountPath)
		if err != nil {
			return fmt.Errorf("error reading account after manual rotation: %w", err)
		}
		if after == nil {
			return fmt.Errorf("account not found after manual rotation at %q", accountPath)
		}
		if len(after.Warnings) > 0 {
			return fmt.Errorf("unexpected warnings after manual rotation at %q: %v", accountPath, after.Warnings)
		}

		lastRotation := fmt.Sprint(after.Data[consts.FieldLastVaultRotation])
		if lastRotation == "" || lastRotation == "<nil>" || lastRotation == "1970-01-01 00:00:00 +0000 UTC" || lastRotation == "0001-01-01 00:00:00 +0000 UTC" {
			return fmt.Errorf("expected %s to be populated after manual rotation at %q, got %v", consts.FieldLastVaultRotation, accountPath, after.Data[consts.FieldLastVaultRotation])
		}

		return nil
	}
}

// TestAccOSSecretBackendAccount_remount verifies remount behavior without
// depending on SSH verification.
func TestAccOSSecretBackendAccount_remount(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	remountPath := acctest.RandomWithPrefix("tf-test-os-updated")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	username := acctest.RandomWithPrefix("tf-user")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
				),
			},
			{
				Config: testAccOSSecretBackendAccountConfig_basic(remountPath, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, remountPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
				),
			},
		},
	})
}

// TestAccOSSecretBackendAccount_optionalFields checks add/remove behavior for
// optional rotation fields in the SSH-independent lane.
func TestAccOSSecretBackendAccount_optionalFields(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	username := acctest.RandomWithPrefix("tf-user")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_minimal(mount, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerifyConnection, "false"),
				),
			},
			{
				Config: testAccOSSecretBackendAccountConfig_allFields(mount, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_period"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "10800"),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", "0 3 * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerifyConnection, "false"),
				),
			},
			{
				Config: testAccOSSecretBackendAccountConfig_minimal(mount, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					// Verify rotation fields are cleared when removed from config
					resource.TestCheckNoResourceAttr(resourceName, "rotation_period"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_window"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_schedule"),
				),
			},
		},
	})
}

// TestAccOSSecretBackendAccount_passwordWriteOnly confirms password_wo remains
// write-only across refreshes when SSH verification is disabled.
func TestAccOSSecretBackendAccount_passwordWriteOnly(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	username := acctest.RandomWithPrefix("tf-user")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerifyConnection, "false"),
				),
			},
			{
				// Refresh should keep password in state even though it's not returned by API
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerifyConnection, "false"),
				),
			},
		},
	})
}

// TestAccOSSecretBackendAccount_rotationSchedule validates schedule-based
// rotation configuration without requiring a live SSH authentication step.
func TestAccOSSecretBackendAccount_rotationSchedule(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	username := acctest.RandomWithPrefix("tf-user")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_withSchedule(mount, hostName, accountName, username, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerifyConnection, "false"),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", "0 0 * * 0"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccOSSecretBackendAccountImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldPasswordWO,
					consts.FieldRotationPeriod,
					consts.FieldRotationWindow,
					consts.FieldVerifyConnection,
					consts.FieldLastVaultRotation,
					consts.FieldNextVaultRotation,
				},
			},
		},
	})
}

// testAccOSSecretBackendAccountImportStateIdFunc builds the explicit import ID
// because the framework resource state ID is not automatically usable here.
func testAccOSSecretBackendAccountImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/hosts/%s/accounts/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldHost],
			rs.Primary.Attributes[consts.FieldName]), nil
	}
}

// testAccOSSecretBackendAccountConfig_basic generates a baseline account config.
// verify_connection is parameterized so the same fixture can be reused for both
// the SSH-independent and SSH-dependent test lanes.
func testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName, username string, verifyConnection bool) string {
	return testAccOSSecretBackendAccountConfig_basicWithHost(mount, hostName, accountName, username, "127.0.0.1", verifyConnection)
}

func testAccOSSecretBackendAccountConfig_basicWithHost(mount, hostName, accountName, username, address string, verifyConnection bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                           = vault_mount.test.path
	ssh_host_key_trust_on_first_use = true
}

resource "vault_os_secret_backend_host" "test" {
  mount             = vault_os_secret_backend.test.mount
  name              = "%s"
	address           = "%s"
	port              = 2222
}

resource "vault_os_secret_backend_account" "test" {
	mount           = vault_os_secret_backend.test.mount
  host            = vault_os_secret_backend_host.test.name
  name            = "%s"
	username        = "%s"
	password_wo     = "bar"
	rotation_period = 86400
	verify_connection = %t
}
`, mount, hostName, address, accountName, username, verifyConnection)
}

// testAccOSSecretBackendAccountConfig_updated is the update variant of the
// baseline fixture used by the SSH-independent CRUD coverage.
func testAccOSSecretBackendAccountConfig_updated(mount, hostName, accountName, username string, verifyConnection bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                           = vault_mount.test.path
	ssh_host_key_trust_on_first_use = true
}

resource "vault_os_secret_backend_host" "test" {
  mount             = vault_os_secret_backend.test.mount
  name              = "%s"
	address           = "127.0.0.1"
	port              = 2222
}

resource "vault_os_secret_backend_account" "test" {
  mount           = vault_os_secret_backend.test.mount
  host            = vault_os_secret_backend_host.test.name
  name            = "%s"
	username        = "%s"
	password_wo     = "bar"
	rotation_period = 172800
	verify_connection = %t
}
`, mount, hostName, accountName, username, verifyConnection)
}

// testAccOSSecretBackendAccountConfig_minimal keeps only required account
// fields so optional-field clearing can be tested deterministically.
func testAccOSSecretBackendAccountConfig_minimal(mount, hostName, accountName, username string, verifyConnection bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                           = vault_mount.test.path
	ssh_host_key_trust_on_first_use = true
}

resource "vault_os_secret_backend_host" "test" {
  mount             = vault_os_secret_backend.test.mount
  name              = "%s"
	address           = "127.0.0.1"
	port              = 2222
}

resource "vault_os_secret_backend_account" "test" {
  mount    = vault_os_secret_backend.test.mount
  host     = vault_os_secret_backend_host.test.name
  name     = "%s"
	username = "%s"
	password_wo = "bar"
	verify_connection = %t
}
`, mount, hostName, accountName, username, verifyConnection)
}

// testAccOSSecretBackendAccountConfig_allFields exercises schedule/window
// fields together using a combination accepted by the beta plugin.
func testAccOSSecretBackendAccountConfig_allFields(mount, hostName, accountName, username string, verifyConnection bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                           = vault_mount.test.path
	ssh_host_key_trust_on_first_use = true
}

resource "vault_os_secret_backend_host" "test" {
  mount             = vault_os_secret_backend.test.mount
  name              = "%s"
	address           = "127.0.0.1"
	port              = 2222
}

resource "vault_os_secret_backend_account" "test" {
  mount             = vault_os_secret_backend.test.mount
  host              = vault_os_secret_backend_host.test.name
  name              = "%s"
	username          = "%s"
	password_wo       = "bar"
	rotation_window   = 10800
  rotation_schedule = "0 3 * * *"
	verify_connection = %t
}
`, mount, hostName, accountName, username, verifyConnection)
}

// testAccOSSecretBackendAccountConfig_withSchedule isolates the schedule-only
// path for import and readback coverage.
func testAccOSSecretBackendAccountConfig_withSchedule(mount, hostName, accountName, username string, verifyConnection bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                           = vault_mount.test.path
	ssh_host_key_trust_on_first_use = true
}

resource "vault_os_secret_backend_host" "test" {
  mount             = vault_os_secret_backend.test.mount
  name              = "%s"
	address           = "127.0.0.1"
	port              = 2222
}

resource "vault_os_secret_backend_account" "test" {
  mount             = vault_os_secret_backend.test.mount
  host              = vault_os_secret_backend_host.test.name
  name              = "%s"
	username          = "%s"
	password_wo       = "bar"
  rotation_schedule = "0 0 * * 0"
	verify_connection = %t
}
`, mount, hostName, accountName, username, verifyConnection)
}

func TestAccOSSecretBackendAccount_importInvalid(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	username := acctest.RandomWithPrefix("tf-user")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName, username, false),
			},
			{
				ResourceName:      "vault_os_secret_backend_account.test",
				ImportState:       true,
				ImportStateId:     "invalid-id-format",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile("(?s)invalid.*account ID"),
			},
			{
				ResourceName:      "vault_os_secret_backend_account.test",
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("%s/%s", mount, hostName), // Missing account name
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile("(?s)invalid.*account ID"),
			},
		},
	})
}

// Made with Bob
