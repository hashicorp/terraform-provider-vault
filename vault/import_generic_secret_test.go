// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccGenericSecret_importBasic(t *testing.T) {
	mount := "secretsv1"
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(mount, name),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				ResourceName:            "vault_generic_secret.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"delete_all_versions"},
			},
		},
	})
}

func TestAccGenericSecret_importBasicNS(t *testing.T) {
	// TODO: investigate why namespace field is not honoured during import.
	// Work around is to set the namespace in the provider{} for import.
	t.Skip("VAULT-4254: namespaced resource imports require provider config")

	ns := acctest.RandomWithPrefix("ns")
	mount := "secretsv1"
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resourceName := "vault_generic_secret.test"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfigNS(ns, mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					testResourceGenericSecret_initialCheck(path),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"delete_all_versions"},
			},
		},
	})
}
