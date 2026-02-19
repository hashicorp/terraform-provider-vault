// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccGenericSecret_KVSecrets tests various KV secrets engine scenarios:
// - KV v1 basic read
// - KV v2 basic read
// - Reading specific version from KV v2
// - with_lease_start_time attribute
// - Different datatype values (string, number, bool, array, object)
// - Empty string values
func TestAccGenericSecret_KVSecrets(t *testing.T) {
	// Variables for KV v1 test
	kvV1Mount := acctest.RandomWithPrefix("kvv1-mount")
	kvV1Path := acctest.RandomWithPrefix("secret")

	// Variables for KV v2 test
	kvV2Mount := acctest.RandomWithPrefix("kvv2-mount")
	kvV2Path := acctest.RandomWithPrefix("secret")

	// Variables for version test
	versionMount := acctest.RandomWithPrefix("kvv2-version-mount")
	versionPath := acctest.RandomWithPrefix("secret")

	// Variables for lease start time test
	leaseMount := acctest.RandomWithPrefix("kv-lease-mount")
	leasePath := acctest.RandomWithPrefix("secret")

	// Variables for different datatype values test
	datatypeMount := acctest.RandomWithPrefix("kv-datatype-mount")
	datatypePath := acctest.RandomWithPrefix("secret")

	// Variables for empty values test
	emptyMount := acctest.RandomWithPrefix("kv-empty-mount")
	emptyPath := acctest.RandomWithPrefix("secret")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			// ==================== KV v1 Tests ====================
			{
				// Setup: Create KV v1 mount and secret
				Config: testGenericSecretConfig_KVV1Setup(kvV1Mount, kvV1Path),
			},
			{
				// Test: Read from KV v1 secrets engine
				Config: testGenericSecretConfig_KVV1(kvV1Mount, kvV1Path),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("username"), knownvalue.StringExact("admin")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("password"), knownvalue.StringExact("secret123")),
				},
			},
			// ==================== KV v2 Tests ====================
			{
				// Setup: Create KV v2 mount and secret
				Config: testGenericSecretConfig_KVV2Setup(kvV2Mount, kvV2Path),
			},
			{
				// Test: Read from KV v2 secrets engine
				Config: testGenericSecretConfig_KVV2(kvV2Mount, kvV2Path),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("api_key"), knownvalue.StringExact("my-api-key")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("region"), knownvalue.StringExact("us-west-2")),
				},
			},
			// ==================== Version Tests ====================
			{
				// Setup: Create KV v2 mount with multiple versions
				Config: testGenericSecretConfig_WithVersionSetup(versionMount, versionPath),
			},
			{
				// Test: Read specific version from KV v2
				Config: testGenericSecretConfig_WithVersion(versionMount, versionPath, 1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("value"), knownvalue.StringExact("version1")),
				},
			},
			// ==================== Lease Start Time Tests ====================
			{
				// Setup: Create KV v1 mount and secret for lease test
				Config: testGenericSecretConfig_WithLeaseStartTimeSetup(leaseMount, leasePath),
			},
			{
				// Test: Read with with_lease_start_time attribute
				Config: testGenericSecretConfig_WithLeaseStartTime(leaseMount, leasePath),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("key"), knownvalue.StringExact("value")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.NotNull()),
				},
			},
			// ==================== Different Datatype Values Tests ====================
			{
				// Setup: Create secret with various data types
				Config: testGenericSecretConfig_DifferentDatatypeValuesSetup(datatypeMount, datatypePath),
			},
			{
				// Test: Verify handling of non-string values
				Config: testGenericSecretConfig_DifferentDatatypeValues(datatypeMount, datatypePath),
				ConfigStateChecks: []statecheck.StateCheck{
					// Validate individual data fields with their string representations
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("string_val"), knownvalue.StringExact("text")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("number_val"), knownvalue.StringExact("42")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("bool_val"), knownvalue.StringExact("true")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("array_val"), knownvalue.StringExact(`["one","two","three"]`)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("object_val"), knownvalue.StringExact(`{"nested":"value"}`)),
					// Validate data_json contains the complete JSON structure with all fields
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data_json"), knownvalue.StringRegexp(regexp.MustCompile(`"string_val"\s*:\s*"text"`))),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data_json"), knownvalue.StringRegexp(regexp.MustCompile(`"number_val"\s*:\s*42`))),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data_json"), knownvalue.StringRegexp(regexp.MustCompile(`"bool_val"\s*:\s*true`))),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data_json"), knownvalue.StringRegexp(regexp.MustCompile(`"array_val"\s*:\s*\["one","two","three"\]`))),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data_json"), knownvalue.StringRegexp(regexp.MustCompile(`"object_val"\s*:\s*\{"nested":"value"\}`))),
				},
			},
			// ==================== Empty Values Tests ====================
			{
				// Setup: Create secret with empty string values
				Config: testGenericSecretConfig_EmptyValuesSetup(emptyMount, emptyPath),
			},
			{
				// Test: Verify handling of empty string values
				Config: testGenericSecretConfig_EmptyValues(emptyMount, emptyPath),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("key1"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("key2"), knownvalue.StringExact("")),
				},
			},
		},
	})
}

func testGenericSecretConfig_KVV1Setup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kvv1" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "kvv1" {
	path = "${vault_mount.kvv1.path}/%s"
	data_json = jsonencode({
		username = "admin"
		password = "secret123"
	})
}
`, mount, path)
}

func testGenericSecretConfig_KVV1(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kvv1" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "kvv1" {
	path = "${vault_mount.kvv1.path}/%s"
	data_json = jsonencode({
		username = "admin"
		password = "secret123"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = vault_generic_secret.kvv1.path
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path)
}

func testGenericSecretConfig_KVV2Setup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kvv2" {
	path = "%s"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_kv_secret_v2" "kvv2" {
	mount = vault_mount.kvv2.path
	name = "%s"
	data_json = jsonencode({
		api_key = "my-api-key"
		region = "us-west-2"
	})
}
`, mount, path)
}

func testGenericSecretConfig_KVV2(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kvv2" {
	path = "%s"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_kv_secret_v2" "kvv2" {
	mount = vault_mount.kvv2.path
	name = "%s"
	data_json = jsonencode({
		api_key = "my-api-key"
		region = "us-west-2"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = "${vault_mount.kvv2.path}/data/${vault_kv_secret_v2.kvv2.name}"
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path)
}

func testGenericSecretConfig_WithVersionSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "version" {
	path = "%s"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_kv_secret_v2" "version_v1" {
	mount = vault_mount.version.path
	name = "%s"
	data_json = jsonencode({
		value = "version1"
	})
}

resource "vault_kv_secret_v2" "version_v2" {
	mount = vault_mount.version.path
	name = "%s"
	data_json = jsonencode({
		value = "version2"
	})
	depends_on = [vault_kv_secret_v2.version_v1]
}
`, mount, path, path)
}

func testGenericSecretConfig_WithVersion(mount, path string, version int) string {
	return fmt.Sprintf(`
resource "vault_mount" "version" {
	path = "%s"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_kv_secret_v2" "version_v1" {
	mount = vault_mount.version.path
	name = "%s"
	data_json = jsonencode({
		value = "version1"
	})
}

resource "vault_kv_secret_v2" "version_v2" {
	mount = vault_mount.version.path
	name = "%s"
	data_json = jsonencode({
		value = "version2"
	})
	depends_on = [vault_kv_secret_v2.version_v1]
}

ephemeral "vault_generic_secret" "test" {
	path = "${vault_mount.version.path}/data/${vault_kv_secret_v2.version_v2.name}"
	version = %d
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path, path, version)
}

func testGenericSecretConfig_WithLeaseStartTimeSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "lease" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "lease" {
	path = "${vault_mount.lease.path}/%s"
	data_json = jsonencode({
		key = "value"
	})
}
`, mount, path)
}

func testGenericSecretConfig_WithLeaseStartTime(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "lease" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "lease" {
	path = "${vault_mount.lease.path}/%s"
	data_json = jsonencode({
		key = "value"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = vault_generic_secret.lease.path
	with_lease_start_time = true
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test
}

resource "echo" "test" {}
`, mount, path)
}

func testGenericSecretConfig_DifferentDatatypeValuesSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "datatype" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "datatype" {
	path = "${vault_mount.datatype.path}/%s"
	data_json = jsonencode({
		string_val = "text"
		number_val = 42
		bool_val = true
		array_val = ["one", "two", "three"]
		object_val = {
			nested = "value"
		}
	})
}
`, mount, path)
}

func testGenericSecretConfig_DifferentDatatypeValues(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "datatype" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "datatype" {
	path = "${vault_mount.datatype.path}/%s"
	data_json = jsonencode({
		string_val = "text"
		number_val = 42
		bool_val = true
		array_val = ["one", "two", "three"]
		object_val = {
			nested = "value"
		}
	})
}

ephemeral "vault_generic_secret" "test" {
	path = vault_generic_secret.datatype.path
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test
}

resource "echo" "test" {}
`, mount, path)
}

func testGenericSecretConfig_EmptyValuesSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "empty" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "empty" {
	path = "${vault_mount.empty.path}/%s"
	data_json = jsonencode({
		key1 = ""
		key2 = ""
	})
}
`, mount, path)
}

func testGenericSecretConfig_EmptyValues(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "empty" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "empty" {
	path = "${vault_mount.empty.path}/%s"
	data_json = jsonencode({
		key1 = ""
		key2 = ""
	})
}

ephemeral "vault_generic_secret" "test" {
	path = vault_generic_secret.empty.path
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test
}

resource "echo" "test" {}
`, mount, path)
}

// TestAccGenericSecret_OtherSecretEngines tests reading from non-KV secrets engines:
// - Transit secrets engine (encryption keys)
// - SSH secrets engine (CA-signed certificates)
func TestAccGenericSecret_OtherSecretEngines(t *testing.T) {
	// Variables for Transit test
	transitMount := acctest.RandomWithPrefix("transit")
	keyName := acctest.RandomWithPrefix("key")

	// Variables for SSH test
	sshMount := acctest.RandomWithPrefix("ssh")
	roleName := acctest.RandomWithPrefix("role")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			// ==================== Transit Secrets Engine Tests ====================
			{
				// Setup: Create Transit mount and encryption key
				Config: testGenericSecretConfig_TransitKeySetup(transitMount, keyName),
			},
			{
				// Test: Read Transit key metadata using ephemeral resource
				Config: testGenericSecretConfig_TransitKey(transitMount, keyName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("name"), knownvalue.StringExact(keyName)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("type"), knownvalue.StringExact("aes256-gcm96")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("keys"), knownvalue.NotNull()),
				},
			},
			// ==================== SSH Secrets Engine Tests ====================
			{
				// Setup: Create SSH mount, CA, and role
				Config: testGenericSecretConfig_SSHRoleSetup(sshMount, roleName),
			},
			{
				// Test: Read SSH role configuration using ephemeral resource
				Config: testGenericSecretConfig_SSHRole(sshMount, roleName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("key_type"), knownvalue.StringExact("ca")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("default_user"), knownvalue.StringExact("ubuntu")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("allowed_users"), knownvalue.StringExact("ubuntu,root")),
				},
			},
		},
	})
}

func testGenericSecretConfig_TransitKeySetup(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
	path = "%s"
	type = "transit"
}

resource "vault_transit_secret_backend_key" "key" {
	backend          = vault_mount.transit.path
	name             = "%s"
	type             = "aes256-gcm96"
	deletion_allowed = true
}
`, mount, keyName)
}

func testGenericSecretConfig_TransitKey(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
	path = "%s"
	type = "transit"
}

resource "vault_transit_secret_backend_key" "key" {
	backend          = vault_mount.transit.path
	name             = "%s"
	type             = "aes256-gcm96"
	deletion_allowed = true
}

ephemeral "vault_generic_secret" "transit_key" {
	path = "${vault_mount.transit.path}/keys/${vault_transit_secret_backend_key.key.name}"
}

provider "echo" {
	data = ephemeral.vault_generic_secret.transit_key.data
}

resource "echo" "test" {}
`, mount, keyName)
}

func testGenericSecretConfig_SSHRoleSetup(mount, roleName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "ssh" {
	path = "%s"
	type = "ssh"
}

resource "vault_ssh_secret_backend_ca" "ca" {
	backend              = vault_mount.ssh.path
	generate_signing_key = true
}

resource "vault_ssh_secret_backend_role" "role" {
	backend                 = vault_mount.ssh.path
	name                    = "%s"
	key_type                = "ca"
	default_user            = "ubuntu"
	allowed_users           = "ubuntu,root"
	ttl                     = "3600"
	max_ttl                 = "7200"
	allow_user_certificates = true
	depends_on              = [vault_ssh_secret_backend_ca.ca]
}
`, mount, roleName)
}

func testGenericSecretConfig_SSHRole(mount, roleName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "ssh" {
	path = "%s"
	type = "ssh"
}

resource "vault_ssh_secret_backend_ca" "ca" {
	backend              = vault_mount.ssh.path
	generate_signing_key = true
}

resource "vault_ssh_secret_backend_role" "role" {
	backend                 = vault_mount.ssh.path
	name                    = "%s"
	key_type                = "ca"
	default_user            = "ubuntu"
	allowed_users           = "ubuntu,root"
	ttl                     = "3600"
	max_ttl                 = "7200"
	allow_user_certificates = true
	depends_on              = [vault_ssh_secret_backend_ca.ca]
}

ephemeral "vault_generic_secret" "ssh_role" {
	path = "${vault_mount.ssh.path}/roles/${vault_ssh_secret_backend_role.role.name}"
}

provider "echo" {
	data = ephemeral.vault_generic_secret.ssh_role.data
}

resource "echo" "test" {}
`, mount, roleName)
}

// TestAccGenericSecret_InvalidConfigurations tests various error handling scenarios:
// - Non-existent mount
// - Invalid path (path doesn't exist)
// - Invalid version (version number doesn't exist)
// - Invalid KV v2 path format
func TestAccGenericSecret_InvalidConfigurations(t *testing.T) {
	kvV1Mount := acctest.RandomWithPrefix("kv-mount")
	kvV2Mount := acctest.RandomWithPrefix("kvv2-mount")
	path := acctest.RandomWithPrefix("secret")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			// Test 1: Non-existent mount
			{
				Config:      testGenericSecretConfig_NonExistentMount(),
				ExpectError: regexp.MustCompile("Vault response was nil|no handler for route|no such mount"),
			},
			// Test 2: Invalid path (path doesn't exist in KV v1)
			{
				Config:      testGenericSecretConfig_InvalidPath(kvV1Mount),
				ExpectError: regexp.MustCompile("Vault response was nil"),
			},
			// Test 3: Invalid version number
			{
				Config:      testGenericSecretConfig_InvalidVersion(kvV2Mount, path),
				ExpectError: regexp.MustCompile("Vault response was nil|no value found|not found|Invalid secret version"),
			},
			// Test 4: Invalid KV v2 path (nonexistent secret path)
			{
				Config:      testGenericSecretConfig_InvalidKVV2Path(kvV2Mount, path),
				ExpectError: regexp.MustCompile("Vault response was nil|no value found|not found"),
			},
		},
	})
}

func testGenericSecretConfig_NonExistentMount() string {
	return `
ephemeral "vault_generic_secret" "test" {
	path = "nonexistent-mount/secret"
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`
}

func testGenericSecretConfig_InvalidPath(mount string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

ephemeral "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/nonexistent"
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount)
}

func testGenericSecretConfig_InvalidVersion(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_kv_secret_v2" "test" {
	mount = vault_mount.test.path
	name = "%s"
	data_json = jsonencode({
		key = "value"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/data/${vault_kv_secret_v2.test.name}"
	version = 999
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path)
}

func testGenericSecretConfig_InvalidKVV2Path(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_kv_secret_v2" "test" {
	mount = vault_mount.test.path
	name = "%s"
	data_json = jsonencode({
		key = "value"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/data/nonexistent"
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path)
}
