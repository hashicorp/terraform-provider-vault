//go:build testonly

package fwprovider

import "github.com/hashicorp/terraform-plugin-framework/resource"

func testResources() []func() resource.Resource {
	return pki_external_ca.NewACMEChallengeServerResource
}
