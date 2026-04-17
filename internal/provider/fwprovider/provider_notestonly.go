// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

//go:build !testonly

package fwprovider

import "github.com/hashicorp/terraform-plugin-framework/resource"

func testResources() []func() resource.Resource {
	return nil
}
