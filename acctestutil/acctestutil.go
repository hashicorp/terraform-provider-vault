// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package acctestutil

import (
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	vaultSchema "github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/vault/api"
)

var (
	TestProvider *schema.Provider
)

// testAccProviderConfigure ensures Provider is only configured once
//
// The PreCheck(t) function is invoked for every test and this prevents
// extraneous reconfiguration to the same values each time. However, this does
// not prevent reconfiguration that may happen should the address of
// Provider be errantly reused in ProviderFactories.
var testAccProviderConfigure sync.Once

func TestAccPreCheck(t *testing.T) {
	t.Helper()
	PreCheck(t)
	testutil.FatalTestEnvUnset(t, api.EnvVaultAddress, api.EnvVaultToken)
}

func TestEntPreCheck(t *testing.T) {
	t.Helper()
	PreCheck(t)
	SkipTestAccEnt(t)
	TestAccPreCheck(t)
}

func PreCheck(t *testing.T) {
	t.Helper()

	// only required when running acceptance tests
	if os.Getenv(resource.EnvTfAcc) == "" && os.Getenv(testutil.EnvVarTfAccEnt) == "" {
		return
	}

	testAccProviderConfigure.Do(func() {
		// TODO: Are the registries needed here?
		p := vaultSchema.NewProvider(provider.NewProvider(map[string]*provider.Description{}, map[string]*provider.Description{}))
		TestProvider = p.SchemaProvider()

		rootProviderResource := &schema.Resource{
			Schema: p.SchemaProvider().Schema,
		}
		rootProviderData := rootProviderResource.TestResourceData()
		m, err := provider.NewProviderMeta(rootProviderData)
		if err != nil {
			panic(err)
		}

		TestProvider.SetMeta(m)
	})
}

func SkipTestAccEnt(t *testing.T) {
	t.Helper()
	testutil.SkipTestEnvUnset(t, testutil.EnvVarTfAccEnt)
}

func SkipTestAcc(t *testing.T) {
	t.Helper()
	testutil.SkipTestEnvUnset(t, resource.EnvTfAcc)
}
