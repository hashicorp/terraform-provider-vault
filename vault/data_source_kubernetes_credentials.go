// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldKubernetesNamespace     = "kubernetes_namespace"
	fieldClusterRoleBinding      = "cluster_role_binding"
	fieldServiceAccountNamespace = "service_account_namespace"
	fieldServiceAccountToken     = "service_account_token"
)

func kubernetesServiceAccountTokenDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readKubernetesServiceAccountToken),
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type: schema.TypeString,
				Description: "The Kubernetes secret backend to generate service account " +
					"tokens from.",
				Required: true,
			},
			consts.FieldRole: {
				Type:        schema.TypeString,
				Description: "The name of the role.",
				Required:    true,
			},
			fieldKubernetesNamespace: {
				Type: schema.TypeString,
				Description: "The name of the Kubernetes namespace in which to generate " +
					"the credentials.",
				Required: true,
			},
			fieldClusterRoleBinding: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				Description: "If true, generate a ClusterRoleBinding to grant permissions " +
					"across the whole cluster instead of within a namespace.",
			},
			consts.FieldTTL: {
				Type: schema.TypeString,
				Description: "The TTL of the generated Kubernetes service account token, " +
					"specified in seconds or as a Go duration format string",
				Optional: true,
			},
			fieldServiceAccountName: {
				Type:        schema.TypeString,
				Description: "The name of the service account associated with the token.",
				Computed:    true,
			},
			fieldServiceAccountNamespace: {
				Type:        schema.TypeString,
				Description: "The Kubernetes namespace that the service account resides in.",
				Computed:    true,
			},
			fieldServiceAccountToken: {
				Type:        schema.TypeString,
				Description: "The Kubernetes service account token.",
				Computed:    true,
				Sensitive:   true,
			},
			consts.FieldLeaseID: {
				Type:        schema.TypeString,
				Description: "The lease identifier assigned by Vault.",
				Computed:    true,
			},
			consts.FieldLeaseDuration: {
				Type:        schema.TypeInt,
				Description: "The duration of the lease in seconds.",
				Computed:    true,
			},
			consts.FieldLeaseRenewable: {
				Type:        schema.TypeBool,
				Description: "True if the duration of this lease can be extended through renewal.",
				Computed:    true,
			},
		},
	}
}

func readKubernetesServiceAccountToken(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	data := make(map[string]interface{})
	inputFields := []string{
		fieldKubernetesNamespace,
		fieldClusterRoleBinding,
		consts.FieldTTL,
	}
	for _, k := range inputFields {
		data[k] = d.Get(k)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	path := fmt.Sprintf("%s/creds/%s", backend, role)
	secret, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		return diag.Errorf("no role found at %q", path)
	}

	d.SetId(secret.LeaseID)
	dataFields := []string{
		fieldServiceAccountName,
		fieldServiceAccountNamespace,
		fieldServiceAccountToken,
	}
	for _, k := range dataFields {
		if err := d.Set(k, secret.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q, err=%s", k, err)
		}
	}

	if err := d.Set(consts.FieldLeaseID, secret.LeaseID); err != nil {
		return diag.Errorf("error setting state key %q, err=%s",
			consts.FieldLeaseID, err)
	}
	if err := d.Set(consts.FieldLeaseDuration, secret.LeaseDuration); err != nil {
		return diag.Errorf("error setting state key %q, err=%s",
			consts.FieldLeaseDuration, err)
	}
	if err := d.Set(consts.FieldLeaseRenewable, secret.Renewable); err != nil {
		return diag.Errorf("error setting state key %q, err=%s",
			consts.FieldLeaseRenewable, err)
	}

	return nil
}
