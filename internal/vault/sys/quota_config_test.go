// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccQuotaConfig(t *testing.T) {
	resourceName := "vault_quota_config.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccQuotaConfig(true, true, []string{"auth/token/login", "auth/token/lookup-self"}, []string{"sys/health", "sys/seal-status"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnableRateLimitAuditLogging, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnableRateLimitResponseHeaders, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRateLimitExemptPaths+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRateLimitExemptPaths+".*", "auth/token/login"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldRateLimitExemptPaths+".*", "auth/token/lookup-self"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAbsoluteRateLimitExemptPaths+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAbsoluteRateLimitExemptPaths+".*", "sys/health"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldAbsoluteRateLimitExemptPaths+".*", "sys/seal-status"),
				),
			},
			{
				Config: testAccQuotaConfig(false, false, []string{}, []string{}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnableRateLimitAuditLogging, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnableRateLimitResponseHeaders, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRateLimitExemptPaths+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAbsoluteRateLimitExemptPaths+".#", "0"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        "sys/quotas/config",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldEnableRateLimitAuditLogging,
			},
		},
	})
}

func TestAccQuotaConfigEmpty(t *testing.T) {
	resourceName := "vault_quota_config.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccQuotaConfigDefaults(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnableRateLimitAuditLogging, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnableRateLimitResponseHeaders, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRateLimitExemptPaths+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAbsoluteRateLimitExemptPaths+".#", "0"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        "sys/quotas/config",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldEnableRateLimitAuditLogging,
			},
		},
	})
}

func testAccQuotaConfig(enableAudit, enableHeaders bool, exemptPaths, absoluteExemptPaths []string) string {
	config := "\nresource \"vault_quota_config\" \"test\" {\n"

	if exemptPaths != nil {
		config += fmt.Sprintf("  %s = %s\n", consts.FieldRateLimitExemptPaths, quoteList(exemptPaths))
	}

	if absoluteExemptPaths != nil {
		config += fmt.Sprintf("  %s = %s\n", consts.FieldAbsoluteRateLimitExemptPaths, quoteList(absoluteExemptPaths))
	}

	config += fmt.Sprintf("  %s = %t\n", consts.FieldEnableRateLimitAuditLogging, enableAudit)
	config += fmt.Sprintf("  %s = %t\n", consts.FieldEnableRateLimitResponseHeaders, enableHeaders)
	config += "}\n"

	return config
}

func testAccQuotaConfigDefaults() string {
	return `
resource "vault_quota_config" "test" {
}
`
}

func quoteList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}

	result := "["
	for i, value := range values {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("%q", value)
	}
	result += "]"

	return result
}
