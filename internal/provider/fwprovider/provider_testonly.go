//go:build testonly

package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/resource"
	pki_external_ca "github.com/hashicorp/terraform-provider-vault/internal/vault/secrets/pki-external-ca"
)

func testResources() []func() resource.Resource {
	return []func() resource.Resource{
		pki_external_ca.NewACMEChallengeServerResource,
	}
}
