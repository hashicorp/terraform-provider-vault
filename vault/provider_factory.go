package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-mux/tf5muxserver"
	"github.com/hashicorp/terraform-provider-vault/internal/provider/fwprovider"
	"github.com/hashicorp/terraform-provider-vault/schema"
)

// ProtoV5ProviderServerFactory returns a muxed terraform-plugin-go protocol v5 provider factory function.
// This factory function is suitable for use with the terraform-plugin-go Serve function.
// The primary (Plugin SDK) provider server is also returned (useful for testing).
func ProtoV5ProviderServerFactory(ctx context.Context) (func() tfprotov5.ProviderServer, *schema.Provider, error) {
	primary := schema.NewProvider(Provider())
	servers := []func() tfprotov5.ProviderServer{
		primary.GRPCProvider,
		providerserver.NewProtocol5(fwprovider.New(primary)),
	}

	muxServer, err := tf5muxserver.NewMuxServer(ctx, servers...)
	if err != nil {
		return nil, nil, err
	}

	return muxServer.ProviderServer, primary, nil
}
