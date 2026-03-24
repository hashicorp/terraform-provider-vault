// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralauth_test

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
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// kerberosTestConfig holds all the Kerberos test configuration values
type kerberosTestConfig struct {
	// Kerberos login configuration
	KeytabPath   string
	Krb5ConfPath string
	Username     string
	Service      string
	Realm        string

	// Kerberos backend configuration
	KeytabBase64   string
	ServiceAccount string

	// LDAP configuration
	LdapURL       string
	LdapBindDN    string
	LdapBindPass  string
	LdapUserDN    string
	LdapUserAttr  string
	LdapGroupDN   string
	LdapGroupAttr string
}

// skipTestEnvUnsetKerberos skips the test if any of the required Kerberos environment variables
// are empty/unset. Returns a kerberosTestConfig struct with all the values.
func skipTestEnvUnsetKerberos(t *testing.T) *kerberosTestConfig {
	t.Helper()
	values := testutil.SkipTestEnvUnset(t,
		"VAULT_TEST_KERBEROS_KEYTAB_PATH",
		"VAULT_TEST_KERBEROS_KRB5CONF_PATH",
		"VAULT_TEST_KERBEROS_USERNAME",
		"VAULT_TEST_KERBEROS_SERVICE",
		"VAULT_TEST_KERBEROS_REALM",
		"VAULT_TEST_KERBEROS_KEYTAB_BASE64",
		"VAULT_TEST_KERBEROS_SERVICE_ACCOUNT",
		"VAULT_TEST_KERBEROS_LDAP_URL",
		"VAULT_TEST_KERBEROS_LDAP_BINDDN",
		"VAULT_TEST_KERBEROS_LDAP_BINDPASS",
		"VAULT_TEST_KERBEROS_LDAP_USERDN",
		"VAULT_TEST_KERBEROS_LDAP_USERATTR",
		"VAULT_TEST_KERBEROS_LDAP_GROUPDN",
		"VAULT_TEST_KERBEROS_LDAP_GROUPATTR",
	)

	return &kerberosTestConfig{
		KeytabPath:     values[0],
		Krb5ConfPath:   values[1],
		Username:       values[2],
		Service:        values[3],
		Realm:          values[4],
		KeytabBase64:   values[5],
		ServiceAccount: values[6],
		LdapURL:        values[7],
		LdapBindDN:     values[8],
		LdapBindPass:   values[9],
		LdapUserDN:     values[10],
		LdapUserAttr:   values[11],
		LdapGroupDN:    values[12],
		LdapGroupAttr:  values[13],
	}
}

// TestAccKerberosAuthBackendLoginEphemeralResource_basic tests the Kerberos login ephemeral resource
// Note: This test requires a properly configured Kerberos environment with:
// - A valid keytab file
// - A krb5.conf configuration file
// - A configured LDAP backend
// - A running KDC (Key Distribution Center)
//
// Required environment variables:
//   - VAULT_TEST_KERBEROS_KEYTAB_PATH: Path to the keytab file
//   - VAULT_TEST_KERBEROS_KRB5CONF_PATH: Path to the krb5.conf configuration file
//   - VAULT_TEST_KERBEROS_USERNAME: Username for the keytab entry
//   - VAULT_TEST_KERBEROS_SERVICE: Service principal name (e.g., HTTP/vault.example.com)
//   - VAULT_TEST_KERBEROS_REALM: Kerberos realm name (e.g., EXAMPLE.COM)
//   - VAULT_TEST_KERBEROS_KEYTAB_BASE64: Base64-encoded keytab file content
//   - VAULT_TEST_KERBEROS_SERVICE_ACCOUNT: Service account (e.g., vault/localhost@MYLOCAL.REALM)
//   - VAULT_TEST_KERBEROS_LDAP_URL: LDAP server URL (e.g., ldap://localhost:389)
//   - VAULT_TEST_KERBEROS_LDAP_BINDDN: LDAP bind DN (e.g., cn=admin,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_BINDPASS: LDAP bind password
//   - VAULT_TEST_KERBEROS_LDAP_USERDN: LDAP user DN (e.g., ou=users,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_USERATTR: LDAP user attribute (e.g., uid)
//   - VAULT_TEST_KERBEROS_LDAP_GROUPDN: LDAP group DN (e.g., ou=users,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_GROUPATTR: LDAP group attribute (e.g., cn)
func TestAccKerberosAuthBackendLoginEphemeralResource_basic(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	config := skipTestEnvUnsetKerberos(t)

	mount := acctest.RandomWithPrefix("kerberos-mount")
	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLoginEphemeralResourceConfig_basic(mount, config),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify client_token is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("client_token"),
						knownvalue.StringRegexp(nonEmpty)),
					// Verify accessor is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("accessor"),
						knownvalue.StringRegexp(nonEmpty)),
					// Verify policies are returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("policies"),
						knownvalue.NotNull()),
					// Verify lease_duration is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("lease_duration"),
						knownvalue.NotNull()),
					// Verify renewable flag is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("renewable"),
						knownvalue.NotNull()),
					// Verify entity_id is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("entity_id"),
						knownvalue.StringRegexp(nonEmpty)),
				},
			},
		},
	})
}

func testAccKerberosAuthBackendLoginEphemeralResourceConfig_basic(mount string, config *kerberosTestConfig) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "%s"
  
  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount               = vault_auth_backend.kerberos.path
  keytab_wo           = "%s"
  service_account     = "%s"
}

resource "vault_kerberos_auth_backend_ldap_config" "ldap" {
  mount       = vault_auth_backend.kerberos.path
  url         = "%s"
  binddn      = "%s"
  bindpass_wo = "%s"
  bindpass_wo_version = 1
  userdn      = "%s"
  userattr    = "%s"
  groupdn     = "%s"
  groupattr   = "%s"
}

ephemeral "vault_kerberos_auth_backend_login" "login" {
  mount                    = vault_auth_backend.kerberos.path
  mount_id                 = vault_auth_backend.kerberos.id
  keytab_path              = "%s"
  krb5conf_path            = "%s"
  username                 = "%s"
  service                  = "%s"
  realm                    = "%s"
  disable_fast_negotiation = false
  remove_instance_name     = false
  
  depends_on = [
  vault_kerberos_auth_backend_config.config,
  vault_kerberos_auth_backend_ldap_config.ldap
  ]
}

provider "echo" {
  data = ephemeral.vault_kerberos_auth_backend_login.login
}

resource "echo" "test_kerberos" {}
`, mount, config.KeytabBase64, config.ServiceAccount, config.LdapURL, config.LdapBindDN, config.LdapBindPass,
		config.LdapUserDN, config.LdapUserAttr, config.LdapGroupDN, config.LdapGroupAttr,
		config.KeytabPath, config.Krb5ConfPath, config.Username, config.Service, config.Realm)
}

// TestAccKerberosAuthBackendLoginEphemeralResource_withOptions tests the Kerberos login
// with optional parameters
//
// Required environment variables:
//   - VAULT_TEST_KERBEROS_KEYTAB_PATH: Path to the keytab file
//   - VAULT_TEST_KERBEROS_KRB5CONF_PATH: Path to the krb5.conf configuration file
//   - VAULT_TEST_KERBEROS_USERNAME: Username for the keytab entry
//   - VAULT_TEST_KERBEROS_SERVICE: Service principal name (e.g., HTTP/vault.example.com)
//   - VAULT_TEST_KERBEROS_REALM: Kerberos realm name (e.g., EXAMPLE.COM)
//   - VAULT_TEST_KERBEROS_KEYTAB_BASE64: Base64-encoded keytab file content
//   - VAULT_TEST_KERBEROS_SERVICE_ACCOUNT: Service account (e.g., vault/localhost@MYLOCAL.REALM)
//   - VAULT_TEST_KERBEROS_LDAP_URL: LDAP server URL (e.g., ldap://localhost:389)
//   - VAULT_TEST_KERBEROS_LDAP_BINDDN: LDAP bind DN (e.g., cn=admin,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_BINDPASS: LDAP bind password
//   - VAULT_TEST_KERBEROS_LDAP_USERDN: LDAP user DN (e.g., ou=users,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_USERATTR: LDAP user attribute (e.g., uid)
//   - VAULT_TEST_KERBEROS_LDAP_GROUPDN: LDAP group DN (e.g., ou=users,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_GROUPATTR: LDAP group attribute (e.g., cn)
func TestAccKerberosAuthBackendLoginEphemeralResource_withOptions(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	config := skipTestEnvUnsetKerberos(t)

	mount := acctest.RandomWithPrefix("kerberos-mount")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLoginEphemeralResourceConfig_withOptions(mount, config),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("client_token"),
						knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccKerberosAuthBackendLoginEphemeralResourceConfig_withOptions(mount string, config *kerberosTestConfig) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "%s"
  
  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount               = vault_auth_backend.kerberos.path
  keytab_wo           = "%s"
  service_account     = "%s"
}

resource "vault_kerberos_auth_backend_ldap_config" "ldap" {
  mount       = vault_auth_backend.kerberos.path
  url         = "%s"
  binddn      = "%s"
  bindpass_wo = "%s"
  bindpass_wo_version = 1
  userdn      = "%s"
  userattr    = "%s"
  groupdn     = "%s"
  groupattr   = "%s"
}

ephemeral "vault_kerberos_auth_backend_login" "login" {
  mount                    = vault_auth_backend.kerberos.path
  mount_id                 = vault_auth_backend.kerberos.id
  keytab_path              = "%s"
  krb5conf_path            = "%s"
  username                 = "%s"
  service                  = "%s"
  realm                    = "%s"
  disable_fast_negotiation = true
  remove_instance_name     = true
  
  depends_on = [
  vault_kerberos_auth_backend_config.config,
  vault_kerberos_auth_backend_ldap_config.ldap
  ]
}

provider "echo" {
  data = ephemeral.vault_kerberos_auth_backend_login.login
}

resource "echo" "test_kerberos" {}
`, mount, config.KeytabBase64, config.ServiceAccount, config.LdapURL, config.LdapBindDN, config.LdapBindPass,
		config.LdapUserDN, config.LdapUserAttr, config.LdapGroupDN, config.LdapGroupAttr,
		config.KeytabPath, config.Krb5ConfPath, config.Username, config.Service, config.Realm)
}

// TestAccKerberosAuthBackendLoginEphemeralResource_namespace tests the Kerberos login
// ephemeral resource with resources created in a namespace
//
// Required environment variables:
//   - VAULT_TEST_KERBEROS_KEYTAB_PATH: Path to the keytab file
//   - VAULT_TEST_KERBEROS_KRB5CONF_PATH: Path to the krb5.conf configuration file
//   - VAULT_TEST_KERBEROS_USERNAME: Username for the keytab entry
//   - VAULT_TEST_KERBEROS_SERVICE: Service principal name (e.g., HTTP/vault.example.com)
//   - VAULT_TEST_KERBEROS_REALM: Kerberos realm name (e.g., EXAMPLE.COM)
//   - VAULT_TEST_KERBEROS_KEYTAB_BASE64: Base64-encoded keytab file content
//   - VAULT_TEST_KERBEROS_SERVICE_ACCOUNT: Service account (e.g., vault/localhost@MYLOCAL.REALM)
//   - VAULT_TEST_KERBEROS_LDAP_URL: LDAP server URL (e.g., ldap://localhost:389)
//   - VAULT_TEST_KERBEROS_LDAP_BINDDN: LDAP bind DN (e.g., cn=admin,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_BINDPASS: LDAP bind password
//   - VAULT_TEST_KERBEROS_LDAP_USERDN: LDAP user DN (e.g., ou=users,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_USERATTR: LDAP user attribute (e.g., uid)
//   - VAULT_TEST_KERBEROS_LDAP_GROUPDN: LDAP group DN (e.g., ou=users,dc=mylocal,dc=realm)
//   - VAULT_TEST_KERBEROS_LDAP_GROUPATTR: LDAP group attribute (e.g., cn)
func TestAccKerberosAuthBackendLoginEphemeralResource_namespace(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	config := skipTestEnvUnsetKerberos(t)

	namespace := acctest.RandomWithPrefix("test-namespace")
	mount := acctest.RandomWithPrefix("kerberos-mount")
	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendLoginEphemeralResourceConfig_namespace(namespace, mount, config),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify client_token is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("client_token"),
						knownvalue.StringRegexp(nonEmpty)),
					// Verify accessor is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("accessor"),
						knownvalue.StringRegexp(nonEmpty)),
					// Verify policies are returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("policies"),
						knownvalue.NotNull()),
					// Verify lease_duration is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("lease_duration"),
						knownvalue.NotNull()),
					// Verify renewable flag is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("renewable"),
						knownvalue.NotNull()),
					// Verify entity_id is returned
					statecheck.ExpectKnownValue("echo.test_kerberos",
						tfjsonpath.New("data").AtMapKey("entity_id"),
						knownvalue.StringRegexp(nonEmpty)),
				},
			},
		},
	})
}

func testAccKerberosAuthBackendLoginEphemeralResourceConfig_namespace(namespace, mount string, config *kerberosTestConfig) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_auth_backend" "kerberos" {
  namespace = vault_namespace.test.path
  type      = "kerberos"
  path      = "%s"
  
  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_kerberos_auth_backend_config" "config" {
  namespace           = vault_namespace.test.path
  mount               = vault_auth_backend.kerberos.path
  keytab_wo           = "%s"
  service_account     = "%s"
}

resource "vault_kerberos_auth_backend_ldap_config" "ldap" {
  namespace           = vault_namespace.test.path
  mount               = vault_auth_backend.kerberos.path
  url                 = "%s"
  binddn              = "%s"
  bindpass_wo         = "%s"
  bindpass_wo_version = 1
  userdn              = "%s"
  userattr            = "%s"
  groupdn             = "%s"
  groupattr           = "%s"
}

ephemeral "vault_kerberos_auth_backend_login" "login" {
  namespace                = vault_namespace.test.path
  mount                    = vault_auth_backend.kerberos.path
  mount_id                 = vault_auth_backend.kerberos.id
  keytab_path              = "%s"
  krb5conf_path            = "%s"
  username                 = "%s"
  service                  = "%s"
  realm                    = "%s"
  disable_fast_negotiation = false
  remove_instance_name     = false
  
  depends_on = [
    vault_kerberos_auth_backend_config.config,
    vault_kerberos_auth_backend_ldap_config.ldap
  ]
}

provider "echo" {
  data = ephemeral.vault_kerberos_auth_backend_login.login
}

resource "echo" "test_kerberos" {}
`, namespace, mount, config.KeytabBase64, config.ServiceAccount, config.LdapURL, config.LdapBindDN, config.LdapBindPass,
		config.LdapUserDN, config.LdapUserAttr, config.LdapGroupDN, config.LdapGroupAttr,
		config.KeytabPath, config.Krb5ConfPath, config.Username, config.Service, config.Realm)
}

// TestAccKerberosAuthBackendLoginEphemeralResource_invalidKeytab tests error handling
// when an invalid keytab path is provided, which should trigger SPNEGO token generation error
func TestAccKerberosAuthBackendLoginEphemeralResource_invalidKeytab(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	config := skipTestEnvUnsetKerberos(t)

	mount := acctest.RandomWithPrefix("kerberos-mount")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccKerberosAuthBackendLoginEphemeralResourceConfig_invalidKeytab(mount, config),
				ExpectError: regexp.MustCompile("Error generating Kerberos SPNEGO token"),
			},
		},
	})
}

func testAccKerberosAuthBackendLoginEphemeralResourceConfig_invalidKeytab(mount string, config *kerberosTestConfig) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "%s"
  
  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount               = vault_auth_backend.kerberos.path
  keytab_wo           = "%s"
  service_account     = "%s"
}

resource "vault_kerberos_auth_backend_ldap_config" "ldap" {
  mount       = vault_auth_backend.kerberos.path
  url         = "%s"
  binddn      = "%s"
  bindpass_wo = "%s"
  bindpass_wo_version = 1
  userdn      = "%s"
  userattr    = "%s"
  groupdn     = "%s"
  groupattr   = "%s"
}

ephemeral "vault_kerberos_auth_backend_login" "login" {
  mount                    = vault_auth_backend.kerberos.path
  mount_id                 = vault_auth_backend.kerberos.id
  keytab_path              = "/nonexistent/path/to/keytab"
  krb5conf_path            = "%s"
  username                 = "%s"
  service                  = "%s"
  realm                    = "%s"
  disable_fast_negotiation = false
  remove_instance_name     = false
  
  depends_on = [
    vault_kerberos_auth_backend_config.config,
    vault_kerberos_auth_backend_ldap_config.ldap
  ]
}

provider "echo" {
  data = ephemeral.vault_kerberos_auth_backend_login.login
}

resource "echo" "test_kerberos" {}
`, mount, config.KeytabBase64, config.ServiceAccount, config.LdapURL, config.LdapBindDN, config.LdapBindPass,
		config.LdapUserDN, config.LdapUserAttr, config.LdapGroupDN, config.LdapGroupAttr,
		config.Krb5ConfPath, config.Username, config.Service, config.Realm)
}

// TestAccKerberosAuthBackendLoginEphemeralResource_invalidNamespace tests error handling
// when an invalid namespace is provided, which should trigger login API error
func TestAccKerberosAuthBackendLoginEphemeralResource_invalidNamespace(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	config := skipTestEnvUnsetKerberos(t)

	mount := acctest.RandomWithPrefix("kerberos-mount")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccKerberosAuthBackendLoginEphemeralResourceConfig_invalidNamespace(mount, config),
				ExpectError: regexp.MustCompile("no handler for route"),
			},
		},
	})
}

func testAccKerberosAuthBackendLoginEphemeralResourceConfig_invalidNamespace(mount string, config *kerberosTestConfig) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "%s"
  
  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount               = vault_auth_backend.kerberos.path
  keytab_wo           = "%s"
  service_account     = "%s"
}

resource "vault_kerberos_auth_backend_ldap_config" "ldap" {
  mount       = vault_auth_backend.kerberos.path
  url         = "%s"
  binddn      = "%s"
  bindpass_wo = "%s"
  bindpass_wo_version = 1
  userdn      = "%s"
  userattr    = "%s"
  groupdn     = "%s"
  groupattr   = "%s"
}

ephemeral "vault_kerberos_auth_backend_login" "login" {
  namespace                = "nonexistent-namespace"
  mount                    = vault_auth_backend.kerberos.path
  mount_id                 = vault_auth_backend.kerberos.id
  keytab_path              = "%s"
  krb5conf_path            = "%s"
  username                 = "%s"
  service                  = "%s"
  realm                    = "%s"
  disable_fast_negotiation = false
  remove_instance_name     = false
  
  depends_on = [
    vault_kerberos_auth_backend_config.config,
    vault_kerberos_auth_backend_ldap_config.ldap
  ]
}

provider "echo" {
  data = ephemeral.vault_kerberos_auth_backend_login.login
}

resource "echo" "test_kerberos" {}
`, mount, config.KeytabBase64, config.ServiceAccount, config.LdapURL, config.LdapBindDN, config.LdapBindPass,
		config.LdapUserDN, config.LdapUserAttr, config.LdapGroupDN, config.LdapGroupAttr,
		config.KeytabPath, config.Krb5ConfPath, config.Username, config.Service, config.Realm)
}
