// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/config"
	"github.com/mitchellh/go-homedir"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// How to run the acceptance tests for this provider:
//
// - Obtain an official Vault release from the Vault website at
//   https://vaultproject.io/ and extract the "vault" binary
//   somewhere.
//
// - Run the following to start the Vault server in development mode:
//       vault server -dev
//
// - Take the "Root Token" value printed by Vault as the server started
//   up and set it as the value of the VAULT_TOKEN environment variable
//   in a new shell whose current working directory is the root of the
//   Terraform repository.
//
// - As directed by the Vault server output, set the VAULT_ADDR environment
//   variable. e.g.:
//       export VAULT_ADDR='http://127.0.0.1:8200'
//
// - Run the Terraform acceptance tests as usual:
//       make testacc TEST=./builtin/providers/vault
//
// The tests expect to be run in a fresh, empty Vault and thus do not attempt
// to randomize or otherwise make the generated resource paths unique on
// each run. In case of weird behavior, restart the Vault dev server to
// start over with a fresh Vault. (Remember to reset VAULT_TOKEN.)

const providerName = "vault"

var testInitOnce = sync.Once{}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

var (
	testProvider  *schema.Provider
	testProviders map[string]*schema.Provider
)

func init() {
	initTestProvider()
}

func initTestProvider() {
	testInitOnce.Do(
		func() {
			// only required when running acceptance tests
			if os.Getenv(resource.EnvTfAcc) == "" {
				return
			}

			if testProvider == nil {
				testProvider = Provider()
				testProviders = map[string]*schema.Provider{
					providerName: testProvider,
				}
				rs := &schema.Resource{
					Schema: testProvider.Schema,
				}

				m, err := testProvider.ConfigureFunc(rs.TestResourceData())
				if err != nil {
					panic(err)
				}
				testProvider.SetMeta(m)
			}
		},
	)
}

var providerFactories = map[string]func() (*schema.Provider, error){
	providerName: func() (*schema.Provider, error) {
		initTestProvider()
		return testProvider, nil
	},
}

// A basic token helper script.
const tokenHelperScript = `#!/usr/bin/env bash
echo "helper-token"
`

func TestAccAuthLoginProviderConfigure(t *testing.T) {
	rootProvider := Provider()
	rootProviderResource := &schema.Resource{
		Schema: rootProvider.Schema,
	}
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testutil.TestAccPreCheck(t) },
		Providers: map[string]*schema.Provider{
			"vault": rootProvider,
		},
		Steps: []resource.TestStep{
			{
				Config: testResourceApproleConfig_basic(),
				Check:  testResourceApproleLoginCheckAttrs(t),
			},
		},
	})

	rootProviderData := rootProviderResource.TestResourceData()
	if _, err := provider.NewProviderMeta(rootProviderData); err != nil {
		t.Fatal(err)
	}
}

func TestTokenReadProviderConfigureWithHeaders(t *testing.T) {
	rootProvider := Provider()

	rootProviderResource := &schema.Resource{
		Schema: rootProvider.Schema,
	}
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testHeaderConfig("auth", "123"),
				Check:  checkSelfToken("display_name", "token-testtoken"),
			},
		},
	})

	rootProviderData := rootProviderResource.TestResourceData()
	if _, err := provider.NewProviderMeta(rootProviderData); err != nil {
		t.Fatal(err)
	}
}

func TestAccNamespaceProviderConfigure(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	rootProvider := Provider()
	rootProviderResource := &schema.Resource{
		Schema: rootProvider.Schema,
	}
	rootProviderData := rootProviderResource.TestResourceData()
	if _, err := provider.NewProviderMeta(rootProviderData); err != nil {
		t.Fatal(err)
	}

	namespacePath := acctest.RandomWithPrefix("test-namespace")

	// Create a test namespace and make sure it stays there
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testutil.TestAccPreCheck(t) },
		Providers: map[string]*schema.Provider{
			"vault": rootProvider,
		},
		Steps: []resource.TestStep{
			{
				Config: testNamespaceConfig(namespacePath),
				Check:  testNamespaceCheckAttrs(),
			},
		},
	})

	nsProvider := Provider()
	nsProviderResource := &schema.Resource{
		Schema: nsProvider.Schema,
	}
	nsProviderData := nsProviderResource.TestResourceData()
	nsProviderData.Set("namespace", namespacePath)
	nsProviderData.Set("token", os.Getenv(api.EnvVaultToken))
	if _, err := provider.NewProviderMeta(nsProviderData); err != nil {
		t.Fatal(err)
	}

	// Create a policy with sudo permissions and an orphaned periodic token within the test namespace
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testutil.TestAccPreCheck(t) },
		Providers: map[string]*schema.Provider{
			"vault": nsProvider,
		},
		Steps: []resource.TestStep{
			{
				Config: testResourceAdminPeriodicOrphanTokenConfig_basic(),
				Check:  testResourceAdminPeriodicOrphanTokenCheckAttrs(namespacePath, t),
			},
		},
	})
}

func testResourceApproleConfig_basic() string {
	return `
resource "vault_auth_backend" "approle" {
	type = "approle"
	path = "approle"
}

resource "vault_policy" "admin" {
    name = "admin"
	policy = <<EOT
path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
EOT
}

resource "vault_approle_auth_backend_role" "admin" {
    backend = vault_auth_backend.approle.path
	role_name = "admin"
	token_policies = [vault_policy.admin.name]
}

resource "vault_approle_auth_backend_role_secret_id" "admin" {
	backend = vault_auth_backend.approle.path
	role_name = vault_approle_auth_backend_role.admin.role_name
}
`
}

func testResourceApproleLoginCheckAttrs(t *testing.T) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_approle_auth_backend_role_secret_id.admin"]
		if resourceState == nil {
			return fmt.Errorf("approle secret id resource not found in state")
		}

		roleResourceState := s.Modules[0].Resources["vault_approle_auth_backend_role.admin"]
		if roleResourceState == nil {
			return fmt.Errorf("approle role resource not found in state")
		}

		backendResourceState := s.Modules[0].Resources["vault_auth_backend.approle"]
		if backendResourceState == nil {
			return fmt.Errorf("approle mount resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("approle secret id resource has no primary instance")
		}

		roleId := roleResourceState.Primary.Attributes["role_id"]
		secretId := instanceState.Attributes["secret_id"]

		authLoginData := []map[string]interface{}{
			{
				"path": "auth/approle/login",
				"parameters": map[string]interface{}{
					"role_id":   roleId,
					"secret_id": secretId,
				},
			},
		}
		approleProvider := Provider()
		approleProviderResource := &schema.Resource{
			Schema: approleProvider.Schema,
		}
		approleProviderData := approleProviderResource.TestResourceData()
		approleProviderData.Set(consts.FieldAuthLoginDefault, authLoginData)
		_, err := provider.NewProviderMeta(approleProviderData)
		if err != nil {
			t.Fatal(err)
		}
		return nil
	}
}

func testResourceAdminPeriodicOrphanTokenConfig_basic() string {
	return `
resource "vault_policy" "test" {
	name = "admin"
	policy = <<EOT
path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
EOT
}

resource "vault_token" "test" {
	policies = [ vault_policy.test.name ]
	ttl = "60s"
}`
}

func testResourceAdminPeriodicOrphanTokenCheckAttrs(namespacePath string, t *testing.T) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Check that it made the policy
		resourceState := s.Modules[0].Resources["vault_policy.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		// Check that it made the token and read it back

		tokenResourceState := s.Modules[0].Resources["vault_token.test"]
		if tokenResourceState == nil {
			return fmt.Errorf("token resource not found in state")
		}

		tokenInstanceState := tokenResourceState.Primary
		if tokenInstanceState == nil {
			return fmt.Errorf("token resource has no primary instance")
		}

		vaultToken := tokenResourceState.Primary.Attributes["client_token"]

		ns2Provider := Provider()
		ns2ProviderResource := &schema.Resource{
			Schema: ns2Provider.Schema,
		}
		ns2ProviderData := ns2ProviderResource.TestResourceData()
		ns2ProviderData.Set("namespace", namespacePath)
		ns2ProviderData.Set("token", vaultToken)
		if _, err := provider.NewProviderMeta(ns2ProviderData); err != nil {
			t.Fatal(err)
		}

		ns2Path := acctest.RandomWithPrefix("test-namespace2")

		// Finally test that you can do stuff with the new token by creating a sub namespace
		resource.Test(t, resource.TestCase{
			PreCheck: func() { testutil.TestAccPreCheck(t) },
			Providers: map[string]*schema.Provider{
				"vault": ns2Provider,
			},
			Steps: []resource.TestStep{
				{
					Config: testNamespaceConfig(ns2Path),
					Check:  testNamespaceCheckAttrs(),
				},
			},
		})

		return nil
	}
}

func TestAccProviderToken(t *testing.T) {
	// This is an acceptance test because it requires filesystem and env var
	// changes that could interfere with other Vault operations.
	testutil.SkipTestAcc(t)

	// Clear the token file if it exists and restore it after the test.
	tokenFilePath, err := homedir.Expand("~/.vault-token")
	if err != nil {
		t.Fatal(err)
	}
	origTokenBytes, err := ioutil.ReadFile(tokenFilePath)
	if err == nil {
		// There is an existing token file. Ensure it is restored after this test.
		info, err := os.Stat(tokenFilePath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			err := ioutil.WriteFile(tokenFilePath, origTokenBytes, info.Mode())
			if err != nil {
				t.Fatal(err)
			}
		}()
		// Delete the existing token file for a clean slate.
		if err := os.Remove(tokenFilePath); err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// Clear the config file env var and restore it after the test.
	reset, err := tempUnsetenv(config.ConfigPathEnv)
	defer failIfErr(t, reset)
	if err != nil {
		t.Fatal(err)
	}

	// Create a "resource" we can use for constructing ResourceData.
	p := Provider()
	providerResource := &schema.Resource{
		Schema: p.Schema,
	}

	type testcase struct {
		name          string
		fileToken     bool
		helperToken   bool
		schemaToken   bool
		expectedToken string
	}

	tests := []testcase{
		{
			name:          "None",
			expectedToken: "",
		},
		{
			// The p will read the token file "~/.vault-token".
			name:          "File",
			fileToken:     true,
			expectedToken: "file-token",
		},
		{
			// A custom token helper overrides token file.
			name:          "CustomHelper",
			fileToken:     true,
			helperToken:   true,
			expectedToken: "helper-token",
		},
		{
			// A VAULT_TOKEN env var or hardcoded token overrides all else.
			name:          "Schema",
			fileToken:     true,
			helperToken:   true,
			schemaToken:   true,
			expectedToken: "schema-token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up the file token.
			if tc.fileToken {
				tokenBytes := []byte("file-token")
				err := ioutil.WriteFile(tokenFilePath, tokenBytes, 0o666)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Remove(tokenFilePath); err != nil {
						t.Fatal(err)
					}
				}()
			}

			// Set up the custom helper token.
			if tc.helperToken {
				cleanup := setupTestTokenHelper(t, tokenHelperScript)
				defer cleanup()
			}

			d := providerResource.TestResourceData()
			// Set up the schema token.
			if tc.schemaToken {
				d.Set("token", "schema-token")
			}

			// Get and check the p token.
			token, err := provider.GetToken(d)
			if err != nil {
				t.Fatal(err)
			}
			if token != tc.expectedToken {
				t.Errorf("bad token value: want %#v, got %#v", tc.expectedToken, token)
			}
		})
	}
}

func TestAccTokenName(t *testing.T) {
	defer os.Unsetenv("VAULT_TOKEN_NAME")
	tests := []struct {
		TokenNameEnv       string
		UseTokenNameEnv    bool
		TokenNameSchema    string
		UseTokenNameSchema bool
		WantTokenName      string
	}{
		{
			UseTokenNameSchema: false,
			UseTokenNameEnv:    false,
			WantTokenName:      "token-terraform",
		},
		{
			TokenNameEnv:    "MyTokenName",
			UseTokenNameEnv: true,
			WantTokenName:   "token-MyTokenName",
		},
		{
			TokenNameEnv:    "",
			UseTokenNameEnv: true,
			WantTokenName:   "token-terraform",
		},
		{
			TokenNameSchema:    "",
			UseTokenNameSchema: true,
			WantTokenName:      "token-terraform",
		},
		{
			TokenNameEnv:    "My!TokenName",
			UseTokenNameEnv: true,
			WantTokenName:   "token-My-TokenName",
		},
		{
			TokenNameEnv:    "My!Token+*#Name",
			UseTokenNameEnv: true,
			WantTokenName:   "token-My-Token---Name",
		},
		{
			TokenNameSchema:    "MySchemaTokenName",
			UseTokenNameSchema: true,
			WantTokenName:      "token-MySchemaTokenName",
		},
		{
			TokenNameEnv:       "MyEnvTokenName",
			UseTokenNameEnv:    true,
			TokenNameSchema:    "MySchemaTokenName",
			UseTokenNameSchema: true,
			WantTokenName:      "token-MySchemaTokenName",
		},
	}

	for _, test := range tests {
		resource.Test(t, resource.TestCase{
			Providers: testProviders,
			PreCheck:  func() { testutil.TestAccPreCheck(t) },
			Steps: []resource.TestStep{
				{
					PreConfig: func() {
						if test.UseTokenNameEnv {
							err := os.Setenv("VAULT_TOKEN_NAME", test.TokenNameEnv)
							if err != nil {
								t.Fatal(err)
							}
						} else {
							err := os.Unsetenv("VAULT_TOKEN_NAME")
							if err != nil {
								t.Fatal(err)
							}
						}
					},
					Config: testProviderConfig(test.UseTokenNameSchema, `token_name = "`+test.TokenNameSchema+`"`),
					Check:  checkSelfToken("display_name", test.WantTokenName),
				},
			},
		})
	}
}

func TestAccChildToken(t *testing.T) {
	defer os.Unsetenv(consts.EnvVarSkipChildToken)

	checkTokenUsed := func(expectChildToken bool) resource.TestCheckFunc {
		if expectChildToken {
			// If the default child token was created, we expect the token
			// used by the provider was named the default "token-terraform"
			return checkSelfToken("display_name", "token-terraform")
		} else {
			// If the child token setting was disabled, the used token
			// should match the user-provided VAULT_TOKEN
			return checkSelfToken("id", os.Getenv(api.EnvVaultToken))
		}
	}

	tests := []struct {
		skipChildTokenEnv    string
		useChildTokenEnv     bool
		skipChildTokenSchema string
		useChildTokenSchema  bool
		expectChildToken     bool
	}{
		{
			useChildTokenSchema: false,
			useChildTokenEnv:    false,
			expectChildToken:    true,
		},
		{
			skipChildTokenEnv: "",
			useChildTokenEnv:  true,
			expectChildToken:  true,
		},
		{
			skipChildTokenEnv: "true",
			useChildTokenEnv:  true,
			expectChildToken:  false,
		},
		{
			skipChildTokenEnv: "false",
			useChildTokenEnv:  true,
			expectChildToken:  true,
		},
		{
			skipChildTokenSchema: "true",
			useChildTokenSchema:  true,
			expectChildToken:     false,
		},
		{
			skipChildTokenSchema: "false",
			useChildTokenSchema:  true,
			expectChildToken:     true,
		},
		{
			skipChildTokenEnv:    "true",
			useChildTokenEnv:     true,
			skipChildTokenSchema: "false",
			useChildTokenSchema:  true,
			expectChildToken:     true,
		},
		{
			skipChildTokenEnv:    "false",
			useChildTokenEnv:     true,
			skipChildTokenSchema: "true",
			useChildTokenSchema:  true,
			expectChildToken:     false,
		},
	}

	for _, test := range tests {
		resource.Test(t, resource.TestCase{
			Providers: testProviders,
			PreCheck:  func() { testutil.TestAccPreCheck(t) },
			Steps: []resource.TestStep{
				{
					PreConfig: func() {
						if test.useChildTokenEnv {
							err := os.Setenv(consts.EnvVarSkipChildToken, test.skipChildTokenEnv)
							if err != nil {
								t.Fatal(err)
							}
						} else {
							err := os.Unsetenv(consts.EnvVarSkipChildToken)
							if err != nil {
								t.Fatal(err)
							}
						}
					},
					Config: testProviderConfig(test.useChildTokenSchema, `skip_child_token = `+test.skipChildTokenSchema),
					Check:  checkTokenUsed(test.expectChildToken),
				},
			},
		})
	}
}

func testHeaderConfig(headerName, headerValue string) string {
	providerConfig := fmt.Sprintf(`
		headers {
			name  = "%s"
			value = "%s"
		}
		token_name = "testtoken"
	`, headerName, headerValue)
	return testProviderConfig(true, providerConfig)
}

// Using the data lookup generic_secret to inspect used token
// by terraform (this enables check of token name)
func testProviderConfig(includeProviderConfig bool, config string) string {
	providerConfig := fmt.Sprintf(`
	provider "vault" {
		%s
	}`, config)

	dataConfig := `
	data "vault_generic_secret" "test" {
		path = "/auth/token/lookup-self"
	}`
	if includeProviderConfig {
		return providerConfig + dataConfig
	}
	return dataConfig
}

func checkSelfToken(attrName string, expectedValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["data.vault_generic_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
		}

		iState := resourceState.Primary
		if iState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		actualValue, ok := resourceState.Primary.Attributes["data."+attrName]
		if !ok {
			return fmt.Errorf("cannot access attribute [%s] for check", attrName)
		}

		if actualValue != expectedValue {
			return fmt.Errorf("%s [%s] expected, but got [%s]", attrName, expectedValue, actualValue)
		}

		return nil
	}
}

// A token helper script that echos back the VAULT_ADDR value
const echoBackTokenHelperScript = `#!/usr/bin/env bash
printenv VAULT_ADDR
`

func TestAccProviderVaultAddrEnv(t *testing.T) {
	// This is an acceptance test because it requires filesystem and env var
	// changes that could interfere with other Vault operations.
	testutil.SkipTestAcc(t)

	// Clear the config file env var and restore it after the test.
	resetConfigPathEnv, err := tempUnsetenv(config.ConfigPathEnv)
	defer failIfErr(t, resetConfigPathEnv)
	if err != nil {
		t.Fatal(err)
	}

	// clear BASH_ENV for this test so any cmd.Exec invocations do not source the BASH_ENV
	// file which is configured with a VAULT_ADDR here:
	// https://github.com/hashicorp/terraform-provider-vault/blob/f42716aae3aebc8daf9702dfa20ce3f8d09d9f4d/.circleci/config.yml#L27
	// All values set in that BASH_ENV file will still be in the process environment of this
	// test, they just won't clobber any values this test modifies in the process environment
	// when the ExternalTokenHelper's command is formatted into a shell invocation to exec here:
	// https://github.com/hashicorp/vault/blob/master/command/token/helper_external.go#L117-L132
	//
	resetBashEnvEnv, err := tempUnsetenv("BASH_ENV")
	defer failIfErr(t, resetBashEnvEnv)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		// vaultAddrEnv is set prior to the provider being instantiated or called
		// simulating any value the user or program may have in its existing environment
		vaultAddrEnv            string
		providerAddress         string
		providerAddAddressToEnv string
		expectedToken           string
	}{
		{
			// If add_address_to_env is not configured at all, do not add the address to the env
			name:                    "AddAddressToEnvNotConfigured",
			providerAddAddressToEnv: "",
			providerAddress:         "https://provider.example.com",
			vaultAddrEnv:            "https://pretest-env-var.example.com",
			expectedToken:           "https://pretest-env-var.example.com",
		},
		{
			name:                    "AddAddressToEnvIsFalse",
			providerAddAddressToEnv: "false",
			providerAddress:         "https://provider.example.com",
			vaultAddrEnv:            "https://pretest-env-var.example.com",
			expectedToken:           "https://pretest-env-var.example.com",
		},
		{
			name:                    "AddAddressToEnvIsTrue",
			providerAddAddressToEnv: "true",
			providerAddress:         "https://provider.example.com",
			vaultAddrEnv:            "https://pretest-env-var.example.com",
			expectedToken:           "https://provider.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.vaultAddrEnv != "" {
				unset, err := tempSetenv(api.EnvVaultAddress, tc.vaultAddrEnv)
				defer failIfErr(t, unset)
				if err != nil {
					t.Fatal(err)
				}
			}

			cleanup := setupTestTokenHelper(t, echoBackTokenHelperScript)
			defer cleanup()

			d, err := newTestResourceData(tc.providerAddress, tc.providerAddAddressToEnv)
			if err != nil {
				t.Fatal(err)
			}

			// Get and check the provider token.
			token, err := provider.GetToken(d)
			if err != nil {
				t.Fatal(err)
			}
			if token != tc.expectedToken {
				t.Errorf("bad token value: want %#v, got %#v", tc.expectedToken, token)
			}
		})
	}
}

func newTestResourceData(address string, addAddressToEnv string) (*schema.ResourceData, error) {
	// Create a "resource" we can use for constructing ResourceData.
	provider := Provider()
	providerResource := &schema.Resource{
		Schema: provider.Schema,
		// this needs to be configured with and without add_Address_to_env
	}

	d := providerResource.TestResourceData()
	err := d.Set("address", address)
	if err != nil {
		return nil, err
	}

	if addAddressToEnv != "" {
		err = d.Set("add_address_to_env", addAddressToEnv)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}

func failIfErr(t *testing.T, f func() error) {
	if err := f(); err != nil {
		t.Fatal(err)
	}
}

// tempUnsetenv is the equivalent of calling `os.Unsetenv` but returns
// a function that be called to restore the modified environment variable
// to its state prior to this function being called.
// The reset function will never be nil.
func tempUnsetenv(key string) (reset func() error, err error) {
	reset = resetEnvFunc(key)
	err = os.Unsetenv(key)
	return reset, err
}

// tempSetenv is the equivalent of calling `os.Setenv` but returns
// a function that be called to restore the modified environment variable
// to its state prior to this function being called.
// The reset function will never be nil.
func tempSetenv(key string, value string) (reset func() error, err error) {
	reset = resetEnvFunc(key)
	err = os.Setenv(key, value)
	return reset, err
}

// resetEnvFunc returns a func that will reset the state of
// the environment variable named `key` when it is called to the
// state captured at the time the function was created
func resetEnvFunc(key string) (reset func() error) {
	if current, exists := os.LookupEnv(key); exists {
		return func() error {
			return os.Setenv(key, current)
		}
	} else {
		return func() error {
			return os.Unsetenv(key)
		}
	}
}

// setupTestTokenHelper creates a temporary vault config that uses the provided
// script as a token helper and returns a cleanup function that should be deferred and
// called to set back the environment to how it was were pre test.
func setupTestTokenHelper(t *testing.T, script string) (cleanup func()) {
	// Use a temp dir for test files.
	dir, err := ioutil.TempDir("", "terraform-provider-vault")
	if err != nil {
		t.Fatal(err)
	}

	// Write out the config file and helper script file.
	configPath := path.Join(dir, "vault-config")
	helperPath := path.Join(dir, "helper-script")
	configStr := fmt.Sprintf(`token_helper = "%s"`, helperPath)
	err = ioutil.WriteFile(configPath, []byte(configStr), 0o666)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(helperPath, []byte(script), 0o777)
	if err != nil {
		t.Fatal(err)
	}
	// Point Vault at the config file.
	os.Setenv(config.ConfigPathEnv, configPath)
	if err != nil {
		t.Fatal(err)
	}

	return func() {
		if err := os.Unsetenv(config.ConfigPathEnv); err != nil {
			t.Fatal(err)
		}

		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
}
