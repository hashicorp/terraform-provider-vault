// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAuthBackend_importBasic(t *testing.T) {
	path := "github-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceAuth_initialConfig(path),
				Check:  testResourceAuth_initialCheck(path),
			},
			{
				ResourceName:            "vault_auth_backend.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldDisableRemount},
			},
		},
	})
}
