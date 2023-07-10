// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldTidyCertStore = "tidy_cert_store"
)

func pkiSecretBackendConfigAutoTidyResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: pkiSecretBackendConfigAutoTidyCreateUpdate,
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendConfigAutoTidyRead),
		UpdateContext: pkiSecretBackendConfigAutoTidyCreateUpdate,
		DeleteContext: pkiSecretBackendConfigAutoTidyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path of the PKI secret backend the resource belongs to.",
			},
			fieldTidyCertStore: {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Specifies whether to tidy up the certificate store.",
			},
			"tidy_revoked_certs": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Set to true to remove all invalid and expired certificates from storage. A revoked storage entry is considered invalid if the entry is empty, or the value within the entry is empty. If a certificate is removed due to expiry, the entry will also be removed from the CRL, and the CRL will be rotated.",
			},
			"tidy_revoked_cert_issuer_associations": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Set to true to associate revoked certificates with their corresponding issuers; this improves the performance of OCSP and CRL building, by shifting work to a tidy operation instead.",
			},
			"tidy_expired_issuers": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Set to true to automatically remove expired issuers after the issuer_safety_buffer duration has elapsed. We log the issuer certificate on removal to allow recovery; no keys are removed during this process.",
			},
			"tidy_move_legacy_ca_bundle": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Set to true to backup any legacy CA/issuers bundle (from Vault versions earlier than 1.11) to config/ca_bundle.bak. This can be restored with sys/raw back to config/ca_bundle if necessary, but won't impact mount startup (as mounts will attempt to read the latter and do a migration of CA issuers if present). Migration will only occur after issuer_safety_buffer has passed since the last successful migration.",
			},
			"tidy_revocation_queue": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Set to true to remove stale revocation request entries that haven't been confirmed by any active node of a performance replication (PR) cluster. Only runs on the active node of the primary cluster.",
			},
			"tidy_cross_cluster_revoked_certs": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Set to true to remove expired, cross-cluster revocation entries. This is the cross-cluster equivalent of tidy_revoked_certs. Only runs on the active node of the primary cluster.",
			},
			"safety_buffer": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Specifies a duration using duration format strings used as a safety buffer to ensure certificates are not expunged prematurely; as an example, this can keep certificates from being removed from the CRL that, due to clock skew, might still be considered valid on other hosts. For a certificate to be expunged, the time must be after the expiration time of the certificate (according to the local clock) plus the duration of safety_buffer. Defaults to 72h.",
			},
			"issuer_safety_buffer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a duration that issuers should be kept for, past their NotAfter validity period. Defaults to 365 days as hours (8760h).",
			},
			"pause_duration": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Specifies the duration to pause between tidying individual certificates. This releases the revocation lock and allows other operations to continue while tidy is paused. This allows an operator to control tidy's resource utilization within a timespan: the LIST operation will remain in memory, but the space between reading, parsing, and updates on-disk cert entries will be increased, decreasing resource utilization.\n\nDoes not affect tidy_expired_issuers.",
			},
			"revocation_queue_safety_buffer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a duration after which cross-cluster revocation requests will be removed as expired. This should be set high enough that, if a cluster disappears for a while but later comes back, any revocation requests which it should process will still be there, but not too long as to fill up storage with too many invalid requests. Defaults to 48h.",
			},
			"tidy_acme": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Set to true to tidy stale ACME accounts, orders, authorizations, EABs, and challenges. ACME orders are tidied (deleted) safety_buffer after the certificate associated with them expires, or after the order and relevant authorizations have expired if no certificate was produced. Authorizations are tidied with the corresponding order.",
			},
			"acme_account_safety_buffer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The amount of time that must pass after creation that an account with no orders is marked revoked, and the amount of time after being marked revoked or deactivated. The default is 30 days as hours.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "Specifies whether automatic tidy is enabled or not.",
			},
			"interval_duration": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Specifies the duration between automatic tidy operations; note that this is from the end of one operation to the start of the next so the time of the operation itself does not need to be considered. Defaults to 12h",
			},
			"maintain_stored_certificate_counts": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "When enabled, maintains expensive counts of certificates. During initialization of the mount, a LIST of all certificates is performed to get a baseline figure and throughout operations like issuance, revocation, and subsequent tidies, the figure is updated.",
			},
			"publish_stored_certificate_count_metrics": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "When enabled, publishes the value computed by maintain_stored_certificate_counts to the mount's metrics. This requires the former to be enabled.",
			},
		},
	}
}

func pkiSecretBackendConfigAutoTidyCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get(consts.FieldBackend).(string)

	path := pkiSecretBackendConfigAutoTidyPath(backend)

	action := "Create"
	if !d.IsNewResource() {
		action = "Update"
	}

	booleanFields := []string{
		fieldTidyCertStore,
		"tidy_revoked_certs",
		"tidy_revoked_cert_issuer_associations",
		"tidy_expired_issuers",
		"tidy_move_legacy_ca_bundle",
		"tidy_revocation_queue",
		"tidy_cross_cluster_revoked_certs",
		"tidy_acme",
		"enabled",
		"maintain_stored_certificate_counts",
		"publish_stored_certificate_count_metrics",
	}

	fields := []string{
		"safety_buffer",
		"issuer_safety_buffer",
		"pause_duration",
		"revocation_queue_safety_buffer",
		"acme_account_safety_buffer",
		"interval_duration",
	}

	data := map[string]interface{}{}
	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	for _, k := range booleanFields {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] %s auto tidy config on PKI secret backend %q", action, backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error writing PKI auto tidy config to %q: %s", backend, err)
	}
	log.Printf("[DEBUG] %sd auto tidy config on PKI secret backend %q", action, backend)

	if d.IsNewResource() {
		d.SetId(fmt.Sprintf("%s/config/auto-tidy", backend))
	}

	return pkiSecretBackendConfigAutoTidyRead(ctx, d, meta)
}

func pkiSecretBackendConfigAutoTidyRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	if path == "" {
		return diag.Errorf("no path set, id=%q", d.Id())
	}

	log.Printf("[DEBUG] Reading auto tidy config from PKI secret path %q", path)
	config, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading auto tidy config on PKI secret backend %q: %s", path, err)
	}

	if config == nil {
		log.Printf("[WARN] Removing auto tidy config path %q as its ID is invalid", path)
		d.SetId("")
		return nil
	}

	fields := []string{
		fieldTidyCertStore,
		"tidy_revoked_certs",
		"tidy_revoked_cert_issuer_associations",
		"tidy_expired_issuers",
		"tidy_move_legacy_ca_bundle",
		"tidy_revocation_queue",
		"tidy_cross_cluster_revoked_certs",
		"safety_buffer",
		"issuer_safety_buffer",
		"pause_duration",
		"revocation_queue_safety_buffer",
		"tidy_acme",
		"acme_account_safety_buffer",
		"enabled",
		"interval_duration",
		"maintain_stored_certificate_counts",
		"publish_stored_certificate_count_metrics",
	}
	for _, k := range fields {
		if err := d.Set(k, config.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func pkiSecretBackendConfigAutoTidyDelete(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	return nil
}

func pkiSecretBackendConfigAutoTidyPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/auto-tidy"
}
