// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource = (*acmeChallengeServerResource)(nil)
)

func NewACMEChallengeServerResource() resource.Resource {
	return &acmeChallengeServerResource{}
}

type acmeChallengeServerResource struct {
	servers map[string]*http.Server
	mu      sync.Mutex
}

type acmeChallengeServerResourceModel struct {
	ID               types.String `tfsdk:"id"`
	Port             types.Int64  `tfsdk:"port"`
	Token            types.String `tfsdk:"token"`
	KeyAuthorization types.String `tfsdk:"key_authorization"`
}

func (r *acmeChallengeServerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_challenge_server"
}

func (r *acmeChallengeServerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Test helper resource that starts an HTTP server to respond to ACME HTTP-01 challenges.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource ID",
			},
			"port": schema.Int64Attribute{
				Required:    true,
				Description: "Port to listen on",
			},
			"token": schema.StringAttribute{
				Required:    true,
				Description: "ACME challenge token",
			},
			"key_authorization": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "ACME challenge key authorization",
			},
		},
	}
}

func (r *acmeChallengeServerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan acmeChallengeServerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.servers == nil {
		r.servers = make(map[string]*http.Server)
	}

	port := plan.Port.ValueInt64()
	token := plan.Token.ValueString()
	keyAuth := plan.KeyAuthorization.ValueString()

	addr := fmt.Sprintf(":%d", port)
	id := fmt.Sprintf("acme-server-%d", port)

	// Create HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/.well-known/acme-challenge/%s", token), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(keyAuth))
	})

	// Create and start server
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Start server in background
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't fail - server might already be stopped
		}
	}()

	r.servers[id] = server

	plan.ID = types.StringValue(id)

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *acmeChallengeServerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state acmeChallengeServerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Nothing to read - just keep the state as-is
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *acmeChallengeServerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All fields require replacement, so this should never be called
	var plan acmeChallengeServerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *acmeChallengeServerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state acmeChallengeServerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	id := state.ID.ValueString()
	if server, ok := r.servers[id]; ok {
		// Shutdown the server
		if err := server.Shutdown(ctx); err != nil {
			resp.Diagnostics.AddWarning(
				"Failed to shutdown ACME challenge server",
				fmt.Sprintf("Error shutting down server: %s", err),
			)
		}
		delete(r.servers, id)
	}
}
