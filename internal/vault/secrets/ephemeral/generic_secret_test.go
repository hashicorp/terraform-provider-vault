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

// TestAccGenericSecret_Basic confirms that a secret written to
// a KV-V1 store in Vault is correctly read into the ephemeral resource
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccGenericSecret_Basic(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kv-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() { acctestutil.SkipTestAcc(t) },
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_BasicSetup(mount, path),
			},
			{
				Config: testGenericSecretConfig_Basic(mount, path),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("zip"), knownvalue.StringExact("zap")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("foo"), knownvalue.StringExact("bar")),
				},
			},
		},
	})
}

func testGenericSecretConfig_BasicSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
	data_json = jsonencode({
		zip = "zap"
		foo = "bar"
	})
}
`, mount, path)
}

func testGenericSecretConfig_Basic(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
	data_json = jsonencode({
		zip = "zap"
		foo = "bar"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = vault_generic_secret.test.path
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path)
}

// TestAccGenericSecret_KVV1 tests reading from KV v1 secrets engine
func TestAccGenericSecret_KVV1(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kvv1-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_KVV1Setup(mount, path),
			},
			{
				Config: testGenericSecretConfig_KVV1(mount, path),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("username"), knownvalue.StringExact("admin")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("password"), knownvalue.StringExact("secret123")),
				},
			},
		},
	})
}

func testGenericSecretConfig_KVV1Setup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
	data_json = jsonencode({
		username = "admin"
		password = "secret123"
	})
}
`, mount, path)
}

func testGenericSecretConfig_KVV1(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
	data_json = jsonencode({
		username = "admin"
		password = "secret123"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = vault_generic_secret.test.path
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path)
}

// TestAccGenericSecret_KVV2 tests reading from KV v2 secrets engine
func TestAccGenericSecret_KVV2(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kvv2-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_KVV2Setup(mount, path),
			},
			{
				Config: testGenericSecretConfig_KVV2(mount, path),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("api_key"), knownvalue.StringExact("my-api-key")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("region"), knownvalue.StringExact("us-west-2")),
				},
			},
		},
	})
}

func testGenericSecretConfig_KVV2Setup(mount, path string) string {
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
		api_key = "my-api-key"
		region = "us-west-2"
	})
}
`, mount, path)
}

func testGenericSecretConfig_KVV2(mount, path string) string {
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
		api_key = "my-api-key"
		region = "us-west-2"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/data/${vault_kv_secret_v2.test.name}"
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path)
}

// TestAccGenericSecret_WithVersion tests reading a specific version
func TestAccGenericSecret_WithVersion(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kvv2-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_WithVersionSetup(mount, path),
			},
			{
				Config: testGenericSecretConfig_WithVersion(mount, path, 1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("value"), knownvalue.StringExact("version1")),
				},
			},
		},
	})
}

func testGenericSecretConfig_WithVersionSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_kv_secret_v2" "test_v1" {
	mount = vault_mount.test.path
	name = "%s"
	data_json = jsonencode({
		value = "version1"
	})
}

resource "vault_kv_secret_v2" "test_v2" {
	mount = vault_mount.test.path
	name = "%s"
	data_json = jsonencode({
		value = "version2"
	})
	depends_on = [vault_kv_secret_v2.test_v1]
}
`, mount, path, path)
}

func testGenericSecretConfig_WithVersion(mount, path string, version int) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_kv_secret_v2" "test_v1" {
	mount = vault_mount.test.path
	name = "%s"
	data_json = jsonencode({
		value = "version1"
	})
}

resource "vault_kv_secret_v2" "test_v2" {
	mount = vault_mount.test.path
	name = "%s"
	data_json = jsonencode({
		value = "version2"
	})
	depends_on = [vault_kv_secret_v2.test_v1]
}

ephemeral "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/data/${vault_kv_secret_v2.test_v2.name}"
	version = %d
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test.data
}

resource "echo" "test" {}
`, mount, path, path, version)
}

// TestAccGenericSecret_WithLeaseStartTime tests with_lease_start_time attribute
func TestAccGenericSecret_WithLeaseStartTime(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kv-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_WithLeaseStartTimeSetup(mount, path),
			},
			{
				Config: testGenericSecretConfig_WithLeaseStartTime(mount, path),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("key"), knownvalue.StringExact("value")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testGenericSecretConfig_WithLeaseStartTimeSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
	data_json = jsonencode({
		key = "value"
	})
}
`, mount, path)
}

func testGenericSecretConfig_WithLeaseStartTime(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
	data_json = jsonencode({
		key = "value"
	})
}

ephemeral "vault_generic_secret" "test" {
	path = vault_generic_secret.test.path
	with_lease_start_time = true
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test
}

resource "echo" "test" {}
`, mount, path)
}

// TestAccGenericSecret_DifferentDatatypeValues tests handling of non-string values
func TestAccGenericSecret_DifferentDatatypeValues(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kv-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_DifferentDatatypeValuesSetup(mount, path),
			},
			{
				Config: testGenericSecretConfig_DifferentDatatypeValues(mount, path),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("string_val"), knownvalue.StringExact("text")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("number_val"), knownvalue.StringExact("42")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("bool_val"), knownvalue.StringExact("true")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("array_val"), knownvalue.StringExact(`["one","two","three"]`)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("object_val"), knownvalue.StringExact(`{"nested":"value"}`)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data_json"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testGenericSecretConfig_DifferentDatatypeValuesSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
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
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
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
	path = vault_generic_secret.test.path
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test
}

resource "echo" "test" {}
`, mount, path)
}

// TestAccGenericSecret_InvalidPath tests error handling when path doesn't exist
func TestAccGenericSecret_InvalidPath(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kv-mount")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testGenericSecretConfig_InvalidPath(mount),
				ExpectError: regexp.MustCompile("Vault response was nil"),
			},
		},
	})
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

// TestAccGenericSecret_InvalidVersion tests error handling when an invalid version number is used
func TestAccGenericSecret_InvalidVersion(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kvv2-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_InvalidVersionSetup(mount, path),
			},
			{
				Config:      testGenericSecretConfig_InvalidVersion(mount, path),
				ExpectError: regexp.MustCompile("Vault response was nil|no value found|not found|Invalid secret version"),
			},
		},
	})
}

func testGenericSecretConfig_InvalidVersionSetup(mount, path string) string {
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
`, mount, path)
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

// TestAccGenericSecret_NonExistentMount tests error handling when mount doesn't exist
func TestAccGenericSecret_NonExistentMount(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testGenericSecretConfig_NonExistentMount(),
				ExpectError: regexp.MustCompile("Vault response was nil|no handler for route|no such mount"),
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

// TestAccGenericSecret_InvalidKVV2Path tests error handling when using wrong path format for KV v2
func TestAccGenericSecret_InvalidKVV2Path(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kvv2-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_InvalidKVV2PathSetup(mount, path),
			},
			{
				Config:      testGenericSecretConfig_InvalidKVV2Path(mount, path),
				ExpectError: regexp.MustCompile("Vault response was nil|no value found|not found"),
			},
		},
	})
}

func testGenericSecretConfig_InvalidKVV2PathSetup(mount, path string) string {
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

// TestAccGenericSecret_EmptyValues tests behavior when secret has keys with empty string values
func TestAccGenericSecret_EmptyValues(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kv-mount")
	path := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_EmptyValuesSetup(mount, path),
			},
			{
				Config: testGenericSecretConfig_EmptyValues(mount, path),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("key1"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("data").AtMapKey("key2"), knownvalue.StringExact("")),
				},
			},
		},
	})
}

func testGenericSecretConfig_EmptyValuesSetup(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
	data_json = jsonencode({
		key1 = ""
		key2 = ""
	})
}
`, mount, path)
}

func testGenericSecretConfig_EmptyValues(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
	path = "${vault_mount.test.path}/%s"
	data_json = jsonencode({
		key1 = ""
		key2 = ""
	})
}

ephemeral "vault_generic_secret" "test" {
	path = vault_generic_secret.test.path
}

provider "echo" {
	data = ephemeral.vault_generic_secret.test
}

resource "echo" "test" {}
`, mount, path)
}

// TestAccGenericSecret_TransitKey tests reading from Transit secrets engine
// Demonstrates using vault_generic_secret with transit type mount
func TestAccGenericSecret_TransitKey(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("transit")
	keyName := acctest.RandomWithPrefix("key")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_TransitKeySetup(mount, keyName),
			},
			{
				Config: testGenericSecretConfig_TransitKey(mount, keyName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("name"), knownvalue.StringExact(keyName)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("type"), knownvalue.StringExact("aes256-gcm96")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("keys"), knownvalue.NotNull()),
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
	backend         = vault_mount.transit.path
	name            = "%s"
	type            = "aes256-gcm96"
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
	backend         = vault_mount.transit.path
	name            = "%s"
	type            = "aes256-gcm96"
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

// TestAccGenericSecret_SSHRole tests reading from SSH secrets engine
// Demonstrates using vault_generic_secret with ssh type mount
func TestAccGenericSecret_SSHRole(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("ssh")
	roleName := acctest.RandomWithPrefix("role")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.SkipTestAcc(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testGenericSecretConfig_SSHRoleSetup(mount, roleName),
			},
			{
				Config: testGenericSecretConfig_SSHRole(mount, roleName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("key_type"), knownvalue.StringExact("ca")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("default_user"), knownvalue.StringExact("ubuntu")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("allowed_users"), knownvalue.StringExact("ubuntu,root")),
				},
			},
		},
	})
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
