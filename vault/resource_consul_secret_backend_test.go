// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

type testMountStore struct {
	uuid string
	path string
}

func TestConsulSecretBackend(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-consul")
	resourceType := "vault_consul_secret_backend"
	resourceName := resourceType + ".test"
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeConsul, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckNoResourceAttr(resourceName, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_key"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key", "disable_remount"),
			{
				Config: testConsulSecretBackend_initialConfigLocal(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "true"),
					resource.TestCheckNoResourceAttr(resourceName, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_key"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key", "disable_remount"),
			{
				Config: testConsulSecretBackend_updateConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckNoResourceAttr(resourceName, "ca_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_cert"),
					resource.TestCheckNoResourceAttr(resourceName, "client_key"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key", "disable_remount"),
			{
				Config: testConsulSecretBackend_updateConfig_addCerts(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, "ca_cert", "FAKE-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourceName, "client_cert", "FAKE-CLIENT-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourceName, "client_key", "FAKE-CLIENT-CERT-KEY-MATERIAL"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key", "disable_remount"),
			{
				Config: testConsulSecretBackend_updateConfig_updateCerts(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, "ca_cert", "FAKE-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourceName, "client_cert", "UPDATED-FAKE-CLIENT-CERT-MATERIAL"),
					resource.TestCheckResourceAttr(resourceName, "client_key", "UPDATED-FAKE-CLIENT-CERT-KEY-MATERIAL"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"token", "bootstrap", "ca_cert", "client_cert", "client_key", "disable_remount"),
		},
	})
}

func TestConsulSecretBackend_Bootstrap(t *testing.T) {
	t.Parallel()
	acctestutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-consul")
	resourceType := "vault_consul_secret_backend"
	resourceName := resourceType + ".test"
	resourceRoleName := "vault_consul_secret_backend_role.test"

	cleanup, consulConfig := testutil.PrepareTestContainer(t, "1.12.3", false, false)
	t.Cleanup(cleanup)
	consulAddr := consulConfig.Address()

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeConsul, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config:      testConsulSecretBackend_bootstrapConfig(path, consulAddr, "", false),
				ExpectError: regexp.MustCompile("field 'bootstrap' must be set to true when neither 'token' nor 'token_wo' is specified"),
			},
			{
				Config:      testConsulSecretBackend_bootstrapConfig(path, consulAddr, "token", true),
				ExpectError: regexp.MustCompile("field 'bootstrap' must be set to false when 'token' or 'token_wo' is specified"),
			},
			{
				Config: testConsulSecretBackend_bootstrapConfig(path, consulAddr, "", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "address", consulAddr),
					resource.TestCheckResourceAttr(resourceName, "bootstrap", "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "token", "bootstrap", "disable_remount"),
			{
				Config: testConsulSecretBackend_bootstrapAddRole(path, consulAddr),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceRoleName, consts.FieldName, "management"),
					resource.TestCheckResourceAttr(resourceRoleName, consts.FieldBackend, path),
					resource.TestCheckResourceAttr(resourceRoleName, "consul_policies.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceRoleName, "consul_policies.*", "global-management"),
				),
			},
			{
				// test graceful remount
				Config: testConsulSecretBackend_bootstrapAddRole(path+"-new", consulAddr),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceRoleName, consts.FieldName, "management"),
					resource.TestCheckResourceAttr(resourceRoleName, consts.FieldBackend, path+"-new"),
					resource.TestCheckResourceAttr(resourceRoleName, "consul_policies.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceRoleName, "consul_policies.*", "global-management"),
				),
			},
			{
				Config:      testConsulSecretBackend_bootstrapAddRoleMulti(path+"-new", consulAddr),
				ExpectError: regexp.MustCompile(`Token not provided and failed to bootstrap ACLs`),
			},
			{
				// ensure that the failure step above did not introduce any side effects.
				Config:   testConsulSecretBackend_bootstrapAddRole(path+"-new", consulAddr),
				PlanOnly: true,
			},
		},
	})
}

func TestConsulSecretBackend_remount(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-consul")
	updatedPath := acctest.RandomWithPrefix("tf-test-consul-updated")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"

	resourceType := "vault_consul_secret_backend"
	resourceName := resourceType + ".test"

	store := &testMountStore{}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeConsul, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
					testCaptureMountUUID(path, store),
				),
			},
			{
				Config: testConsulSecretBackend_initialConfig(updatedPath, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
					testMountCompareUUIDs(updatedPath, store, true),
					testCaptureMountUUID(updatedPath, store),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "token", "bootstrap", "disable_remount"),
			{
				Config: testConsulSecretBackend_disableRemount(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "scheme", "http"),
					resource.TestCheckResourceAttr(resourceName, "disable_remount", "true"),
					testMountCompareUUIDs(path, store, false),
				),
			},
		},
	})
}

func TestConsulSecretBackend_WriteOnlyToken(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-consul-wo")
	resourceType := "vault_consul_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeConsul, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_writeOnlyToken(path, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldTokenWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldToken),
				),
			},
			{
				// Test token rotation via version increment
				Config: testConsulSecretBackend_writeOnlyToken(path, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldTokenWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldToken),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldToken,
					consts.FieldTokenWO,
					consts.FieldTokenWOVersion,
					"bootstrap",
					"ca_cert",
					"client_cert",
					"client_key",
					consts.FieldClientKeyWO,
					consts.FieldClientKeyWOVersion,
					"disable_remount",
				},
			},
		},
	})
}

func TestConsulSecretBackend_WriteOnlyClientKey(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-consul-ck-wo")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resourceType := "vault_consul_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeConsul, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_writeOnlyClientKey(path, token, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientKeyWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, "client_cert", "FAKE-CLIENT-CERT-MATERIAL"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKey),
				),
			},
			{
				// Test client_key rotation via version increment
				Config: testConsulSecretBackend_writeOnlyClientKey(path, token, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientKeyWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKey),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldToken,
					consts.FieldTokenWO,
					consts.FieldTokenWOVersion,
					"bootstrap",
					"ca_cert",
					"client_cert",
					"client_key",
					consts.FieldClientKeyWO,
					consts.FieldClientKeyWOVersion,
					"disable_remount",
				},
			},
		},
	})
}

func TestConsulSecretBackend_WriteOnlyBoth(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-consul-both-wo")
	resourceType := "vault_consul_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeConsul, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_writeOnlyBoth(path, 1, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientKeyWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldTokenWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldToken),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKey),
				),
			},
			{
				// Test rotating both
				Config: testConsulSecretBackend_writeOnlyBoth(path, 2, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenWOVersion, "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientKeyWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldTokenWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldToken),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKey),
				),
			},
		},
	})
}

func TestConsulSecretBackend_LegacyFields(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-consul-legacy")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resourceType := "vault_consul_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeConsul, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_legacyFields(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr(resourceName, "scheme", "https"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldToken, token),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientKey, "FAKE-CLIENT-CERT-KEY-MATERIAL"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldTokenWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldTokenWOVersion),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKeyWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientKeyWOVersion),
				),
			},
		},
	})
}

func TestConsulSecretBackend_WriteOnlyConflicts(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-consul-conflicts")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				// Test token ConflictsWith validation
				Config:      testConsulSecretBackend_tokenConflict(path, token),
				ExpectError: regexp.MustCompile(`.*conflicts with.*`),
			},
			{
				// Test token_wo_version RequiredWith validation
				Config:      testConsulSecretBackend_tokenVersionWithoutToken(path),
				ExpectError: regexp.MustCompile(`all of .+token_wo.+token_wo_version.+ must\s+be\s+specified`),
			},
			{
				// Test client_key ConflictsWith validation
				Config:      testConsulSecretBackend_clientKeyConflict(path, token),
				ExpectError: regexp.MustCompile(`.*conflicts with.*`),
			},
			{
				// Test client_key_wo_version RequiredWith validation
				Config:      testConsulSecretBackend_clientKeyVersionWithoutKey(path, token),
				ExpectError: regexp.MustCompile(`all of .+client_key_wo.+client_key_wo_version.+ must\s+be\s+specified`),
			},
		},
	})
}

func testCaptureMountUUID(path string, store *testMountStore) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		mount, err := testGetMount(path)
		if err != nil {
			return err
		}

		store.path = path
		store.uuid = mount.UUID

		return nil
	}
}

func testMountCompareUUIDs(path string, store *testMountStore, equal bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		mount, err := testGetMount(path)
		if err != nil {
			return err
		}

		if store.uuid == mount.UUID {
			if !equal {
				return fmt.Errorf("expected different uuids after mount creation; "+
					"both uuids equal to %s", store.uuid)
			}
		} else {
			if equal {
				return fmt.Errorf("expected same uuid after remount; "+
					"got id1=%s, id2=%s", store.uuid, mount.UUID)
			}
		}

		return nil
	}
}

func testGetMount(path string) (*api.MountOutput, error) {
	client, err := provider.GetClient("", testProvider.Meta())

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, err
	}

	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		return nil, fmt.Errorf("given mount %s not found", path)
	}

	return mount, nil
}

func testConsulSecretBackend_initialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
}`, path, token)
}

func testConsulSecretBackend_disableRemount(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
  disable_remount = true
}`, path, token)
}

func testConsulSecretBackend_initialConfigLocal(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
  local = true
}`, path, token)
}

func testConsulSecretBackend_bootstrapConfig(path, addr, token string, bootstrap bool) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "%s"
  token = "%s"
  bootstrap = %t
  disable_remount = false
}
`, path, addr, token, bootstrap)
}

func testConsulSecretBackend_updateConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path        = "%s"
  description = "test description"
  address     = "consul.domain.tld:8501"
  token       = "%s"
  scheme      = "https"
}
`, path, token)
}

func testConsulSecretBackend_bootstrapAddRole(path, addr string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path            = "%s"
  description     = "test description"
  address         = "%s"
  bootstrap       = true
  disable_remount = false
}

resource "vault_consul_secret_backend_role" "test" {
  backend         = vault_consul_secret_backend.test.path
  name            = "management"
  consul_policies = ["global-management"]
}
`, path, addr)
}

func testConsulSecretBackend_bootstrapAddRoleMulti(path, addr string) string {
	return fmt.Sprintf(`
%s

resource "vault_consul_secret_backend" "test-2" {
  path            = "%s-2"
  description     = "test description"
  address         = "%s"
  bootstrap       = true
  disable_remount = false
}
`, testConsulSecretBackend_bootstrapAddRole(path, addr), path, addr)
}

func testConsulSecretBackend_updateConfig_addCerts(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "consul.domain.tld:8501"
  token = "%s"
  scheme = "https"
  ca_cert = "FAKE-CERT-MATERIAL"
  client_cert = "FAKE-CLIENT-CERT-MATERIAL"
  client_key = "FAKE-CLIENT-CERT-KEY-MATERIAL"
}`, path, token)
}

func testConsulSecretBackend_updateConfig_updateCerts(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "consul.domain.tld:8501"
  token = "%s"
  scheme = "https"
  ca_cert = "FAKE-CERT-MATERIAL"
  client_cert = "UPDATED-FAKE-CLIENT-CERT-MATERIAL"
  client_key = "UPDATED-FAKE-CLIENT-CERT-KEY-MATERIAL"
}`, path, token)
}

func testConsulSecretBackend_writeOnlyToken(path string, version int) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path                 = "%s"
  description          = "test write-only token"
  address              = "127.0.0.1:8500"
  token_wo             = "test-token-wo-%d"
  token_wo_version     = %d
  scheme               = "http"
}`, path, version, version)
}

func testConsulSecretBackend_writeOnlyClientKey(path, token string, version int) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path                     = "%s"
  description              = "test write-only client_key"
  address                  = "consul.domain.tld:8501"
  token                    = "%s"
  scheme                   = "https"
  ca_cert                  = "FAKE-CERT-MATERIAL"
  client_cert              = "FAKE-CLIENT-CERT-MATERIAL"
  client_key_wo            = "FAKE-CLIENT-KEY-WO-%d"
  client_key_wo_version    = %d
}`, path, token, version, version)
}

func testConsulSecretBackend_writeOnlyBoth(path string, tokenVersion, keyVersion int) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path                     = "%s"
  description              = "test write-only both"
  address                  = "consul.domain.tld:8501"
  token_wo                 = "test-token-wo-%d"
  token_wo_version         = %d
  scheme                   = "https"
  ca_cert                  = "FAKE-CERT-MATERIAL"
  client_cert              = "FAKE-CLIENT-CERT-MATERIAL"
  client_key_wo            = "FAKE-CLIENT-KEY-WO-%d"
  client_key_wo_version    = %d
}`, path, tokenVersion, tokenVersion, keyVersion, keyVersion)
}

func testConsulSecretBackend_legacyFields(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path                     = "%s"
  description              = "test legacy fields"
  address                  = "consul.domain.tld:8501"
  token                    = "%s"
  scheme                   = "https"
  ca_cert                  = "FAKE-CERT-MATERIAL"
  client_cert              = "FAKE-CLIENT-CERT-MATERIAL"
  client_key               = "FAKE-CLIENT-CERT-KEY-MATERIAL"
}`, path, token)
}

// Negative test helper configurations
func testConsulSecretBackend_tokenConflict(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path                 = "%s"
  description          = "test token conflict"
  address              = "127.0.0.1:8500"
  token                = "%s"
  token_wo             = "test-token-wo"
  token_wo_version     = 1
  scheme               = "http"
}`, path, token)
}

func testConsulSecretBackend_tokenVersionWithoutToken(path string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path                 = "%s"
  description          = "test token_wo_version without token_wo"
  address              = "127.0.0.1:8500"
  token_wo_version     = 1
  scheme               = "http"
}`, path)
}

func testConsulSecretBackend_clientKeyConflict(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path                     = "%s"
  description              = "test client_key conflict"
  address                  = "consul.domain.tld:8501"
  token                    = "%s"
  scheme                   = "https"
  ca_cert                  = "FAKE-CERT-MATERIAL"
  client_cert              = "FAKE-CLIENT-CERT-MATERIAL"
  client_key               = "FAKE-CLIENT-KEY"
  client_key_wo            = "FAKE-CLIENT-KEY-WO"
  client_key_wo_version    = 1
}`, path, token)
}

func testConsulSecretBackend_clientKeyVersionWithoutKey(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path                     = "%s"
  description              = "test client_key_wo_version without client_key_wo"
  address                  = "consul.domain.tld:8501"
  token                    = "%s"
  scheme                   = "https"
  ca_cert                  = "FAKE-CERT-MATERIAL"
  client_cert              = "FAKE-CLIENT-CERT-MATERIAL"
  client_key_wo_version    = 1
}`, path, token)
}
