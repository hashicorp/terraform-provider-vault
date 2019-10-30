package vault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/pathorcontents"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/command/config"
	"github.com/mitchellh/go-homedir"
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

func TestProvider(t *testing.T) {
	if err := Provider().(*schema.Provider).InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

var testProvider *schema.Provider
var testProviders map[string]terraform.ResourceProvider

func init() {
	testProvider = Provider().(*schema.Provider)
	testProviders = map[string]terraform.ResourceProvider{
		"vault": testProvider,
	}
}

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("VAULT_ADDR"); v == "" {
		t.Fatal("VAULT_ADDR must be set for acceptance tests")
	}
	if v := os.Getenv("VAULT_TOKEN"); v == "" {
		t.Fatal("VAULT_TOKEN must be set for acceptance tests")
	}
}

func getTestAWSCreds(t *testing.T) (string, string) {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKey == "" {
		t.Skip("AWS_ACCESS_KEY_ID not set")
	}
	if secretKey == "" {
		t.Skip("AWS_SECRET_ACCESS_KEY not set")
	}
	return accessKey, secretKey
}

func getTestGCPCreds(t *testing.T) (string, string) {
	credentials := os.Getenv("GOOGLE_CREDENTIALS")
	project := os.Getenv("GOOGLE_PROJECT")

	if credentials == "" {
		t.Skip("GOOGLE_CREDENTIALS not set")
	}

	if project == "" {
		t.Skip("GOOGLE_PROJECT not set")
	}

	contents, _, err := pathorcontents.Read(credentials)
	if err != nil {
		t.Fatal("Error reading GOOGLE_CREDENTIALS: " + err.Error())
	}

	return string(contents), project
}

func getTestRMQCreds(t *testing.T) (string, string, string) {
	connectionUri := os.Getenv("RMQ_CONNECTION_URI")
	username := os.Getenv("RMQ_USERNAME")
	password := os.Getenv("RMQ_PASSWORD")
	if connectionUri == "" {
		t.Skip("RMQ_CONNECTION_URI not set")
	}
	if username == "" {
		t.Skip("RMQ_USERNAME not set")
	}
	if password == "" {
		t.Skip("RMQ_PASSWORD not set")
	}
	return connectionUri, username, password
}

// A basic token helper script.
const tokenHelperScript = `
#!/usr/bin/env bash
echo "helper-token"
`

func TestAccAuthLoginProviderConfigure(t *testing.T) {
	rootProvider := Provider().(*schema.Provider)
	rootProviderResource := &schema.Resource{
		Schema: rootProvider.Schema,
	}
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
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
	if _, err := providerConfigure(rootProviderData); err != nil {
		t.Fatal(err)
	}
}

func TestAccNamespaceProviderConfigure(t *testing.T) {
	isEnterprise := os.Getenv("TF_ACC_ENTERPRISE")
	if isEnterprise == "" {
		t.Skip("TF_ACC_ENTERPRISE is not set, test is applicable only for Enterprise version of Vault")
	}

	rootProvider := Provider().(*schema.Provider)
	rootProviderResource := &schema.Resource{
		Schema: rootProvider.Schema,
	}
	rootProviderData := rootProviderResource.TestResourceData()
	if _, err := providerConfigure(rootProviderData); err != nil {
		t.Fatal(err)
	}

	namespacePath := acctest.RandomWithPrefix("test-namespace")

	//Create a test namespace and make sure it stays there
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
			"vault": rootProvider,
		},
		Steps: []resource.TestStep{
			{
				Config: testNamespaceConfig(namespacePath),
				Check:  testNamespaceCheckAttrs(),
			},
		},
	})

	nsProvider := Provider().(*schema.Provider)
	nsProviderResource := &schema.Resource{
		Schema: nsProvider.Schema,
	}
	nsProviderData := nsProviderResource.TestResourceData()
	nsProviderData.Set("namespace", namespacePath)
	nsProviderData.Set("token", os.Getenv("VAULT_TOKEN"))
	if _, err := providerConfigure(nsProviderData); err != nil {
		t.Fatal(err)
	}

	// Create a policy with sudo permissions and an orphaned periodic token within the test namespace
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
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
	policies = [vault_policy.admin.name]
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
		approleProvider := Provider().(*schema.Provider)
		approleProviderResource := &schema.Resource{
			Schema: approleProvider.Schema,
		}
		approleProviderData := approleProviderResource.TestResourceData()
		approleProviderData.Set("auth_login", authLoginData)
		_, err := providerConfigure(approleProviderData)
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
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func testResourceAdminPeriodicOrphanTokenCheckAttrs(namespacePath string, t *testing.T) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		//Check that it made the policy
		resourceState := s.Modules[0].Resources["vault_policy.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		//Check that it made the token and read it back

		tokenResourceState := s.Modules[0].Resources["vault_token.test"]
		if tokenResourceState == nil {
			return fmt.Errorf("token resource not found in state")
		}

		tokenInstanceState := tokenResourceState.Primary
		if tokenInstanceState == nil {
			return fmt.Errorf("token resource has no primary instance")
		}

		vaultToken := tokenResourceState.Primary.Attributes["client_token"]

		ns2Provider := Provider().(*schema.Provider)
		ns2ProviderResource := &schema.Resource{
			Schema: ns2Provider.Schema,
		}
		ns2ProviderData := ns2ProviderResource.TestResourceData()
		ns2ProviderData.Set("namespace", namespacePath)
		ns2ProviderData.Set("token", vaultToken)
		if _, err := providerConfigure(ns2ProviderData); err != nil {
			t.Fatal(err)
		}

		ns2Path := acctest.RandomWithPrefix("test-namespace2")

		//Finally test that you can do stuff with the new token by creating a sub namespace
		resource.Test(t, resource.TestCase{
			PreCheck: func() { testAccPreCheck(t) },
			Providers: map[string]terraform.ResourceProvider{
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
	if os.Getenv(resource.TestEnvVar) == "" {
		t.Skip(fmt.Sprintf(
			"Acceptance tests skipped unless env '%s' set",
			resource.TestEnvVar))
	}

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
	origConfigPath, ok := os.LookupEnv(config.ConfigPathEnv)
	if ok {
		// A config path env var was set; ensure we restore it.
		defer func() {
			err := os.Setenv(config.ConfigPathEnv, origConfigPath)
			if err != nil {
				t.Fatal(err)
			}
		}()
	}
	err = os.Unsetenv(config.ConfigPathEnv)
	if err != nil {
		t.Fatal(err)
	}

	// Create a "resource" we can use for constructing ResourceData.
	provider := Provider().(*schema.Provider)
	providerResource := &schema.Resource{
		Schema: provider.Schema,
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
			// The provider will read the token file "~/.vault-token".
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
				err := ioutil.WriteFile(tokenFilePath, tokenBytes, 0666)
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
				// Use a temp dir for test files.
				dir, err := ioutil.TempDir("", "terraform-provider-vault")
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.RemoveAll(dir); err != nil {
						t.Fatal(err)
					}
				}()
				// Write out the config file and helper script file.
				configPath := path.Join(dir, "vault-config")
				helperPath := path.Join(dir, "helper-script")
				configStr := fmt.Sprintf(`token_helper = "%s"`, helperPath)
				err = ioutil.WriteFile(configPath, []byte(configStr), 0666)
				if err != nil {
					t.Fatal(err)
				}
				err = ioutil.WriteFile(helperPath, []byte(tokenHelperScript), 0777)
				if err != nil {
					t.Fatal(err)
				}
				// Point Vault at the config file.
				os.Setenv(config.ConfigPathEnv, configPath)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Unsetenv(config.ConfigPathEnv); err != nil {
						t.Fatal(err)
					}
				}()
			}

			d := providerResource.TestResourceData()
			// Set up the schema token.
			if tc.schemaToken {
				d.Set("token", "schema-token")
			}

			// Get and check the provider token.
			token, err := providerToken(d)
			if err != nil {
				t.Fatal(err)
			}
			if token != tc.expectedToken {
				t.Errorf("bad token value: want %#v, got %#v", tc.expectedToken, token)
			}
		})
	}
}
