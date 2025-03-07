// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendConfigAutoTidyResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(pkiSecretBackendConfigAutoTidyCreateUpdate, provider.VaultVersion112),
		ReadContext:   provider.ReadContextWrapper(pkiSecretBackendConfigAutoTidyRead),
		UpdateContext: pkiSecretBackendConfigAutoTidyCreateUpdate,
		DeleteContext: pkiSecretBackendConfigAutoTidyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: pkiSecretBackendConfigAutoTidySchema(),
	}
}

var pkiSecretBackendConfigAutoTidyDurationFields = map[string]string{
	consts.FieldMinStartupBackoffDuration:   "The minimum amount of time auto-tidy will be delayed after startup.",
	consts.FieldMaxStartupBackoffDuration:   "The maximum amount of time auto-tidy will be delayed after startup.",
	consts.FieldIntervalDuration:            "Interval at which to run an auto-tidy operation. This is the time between tidy invocations (after one finishes to the start of the next).",
	consts.FieldSafetyBuffer:                "The amount of extra time that must have passed beyond certificate expiration before it is removed from the backend storage and/or revocation list.",
	consts.FieldIssuerSafetyBuffer:          "The amount of extra time that must have passed beyond issuer's expiration before it is removed from the backend storage.",
	consts.FieldAcmeAccountSafetyBuffer:     "The amount of time that must pass after creation that an account with no orders is marked revoked, and the amount of time after being marked revoked or deactivated.",
	consts.FieldPauseDuration:               "The amount of time to wait between processing certificates.",
	consts.FieldRevocationQueueSafetyBuffer: "The amount of time that must pass from the cross-cluster revocation request being initiated to when it will be slated for removal.",
}

var pkiSecretBackendConfigAutoTidyBoolFields = map[string]string{
	consts.FieldEnabled:                              "Specifies whether automatic tidy is enabled or not.",
	consts.FieldMaintainStoredCertificateCounts:      "This configures whether stored certificate are counted upon initialization of the backend, and whether during normal operation, a running count of certificates stored is maintained.",
	consts.FieldPublishStoredCertificateCountMetrics: "This configures whether the stored certificate\ncount is published to the metrics consumer.",
	consts.FieldTidyCertStore:                        "Set to true to enable tidying up the certificate store",
	consts.FieldTidyRevokedCerts:                     "Set to true to remove all invalid and expired certificates from storage. A revoked storage entry is considered invalid if the entry is empty, or the value within the entry is empty. If a certificate is removed due to expiry, the entry will also be removed from the CRL, and the CRL will be rotated.",
	consts.FieldTidyRevokedCertIssuerAssociations:    "Set to true to validate issuer associations on revocation entries. This helps increase the performance of CRL building and OCSP responses.",
	consts.FieldTidyExpiredIssuers:                   "Set to true to automatically remove expired issuers past the issuer_safety_buffer. No keys will be removed as part of this operation.",
	consts.FieldTidyMoveLegacyCaBundle:               "Set to true to move the legacy ca_bundle from /config/ca_bundle to /config/ca_bundle.bak.",
	consts.FieldTidyAcme:                             "Set to true to enable tidying ACME accounts, orders and authorizations.",
	consts.FieldTidyRevocationQueue:                  "Set to true to remove stale revocation queue entries that haven't been confirmed by any active cluster.",
	consts.FieldTidyCrossClusterRevokedCerts:         "Set to true to enable tidying up the cross-cluster revoked certificate store.",
	consts.FieldTidyCertMetadata:                     "Set to true to enable tidying up certificate metadata.",
	consts.FieldTidyCmpv2NonceStore:                  "Set to true to enable tidying up the CMPv2 nonce store.",
}

func pkiSecretBackendConfigAutoTidySchema() map[string]*schema.Schema {
	var atLeastOneTidyOperation []string
	var isOneOfField func(string) bool
	{
		atLeastOneOfSet := make(map[string]any)
		for field := range pkiSecretBackendConfigAutoTidyBoolFields {
			if strings.HasPrefix(field, "tidy_") {
				atLeastOneTidyOperation = append(atLeastOneTidyOperation, field)
				atLeastOneOfSet[field] = nil
			}
		}
		isOneOfField = func(field string) bool {
			_, ok := atLeastOneOfSet[field]
			return ok
		}
	}

	ret := map[string]*schema.Schema{
		consts.FieldBackend: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The path of the PKI secret backend the resource belongs to.",
		},
	}

	// Add the boolean fields
	for field, desc := range pkiSecretBackendConfigAutoTidyBoolFields {
		ret[field] = &schema.Schema{
			Type:        schema.TypeBool,
			Optional:    true,
			Description: desc,
		}
		if isOneOfField(field) {
			ret[field].AtLeastOneOf = atLeastOneTidyOperation
		}
	}
	ret[consts.FieldEnabled].Optional = false
	ret[consts.FieldEnabled].Required = true

	// Add the duration fields
	for field, desc := range pkiSecretBackendConfigAutoTidyDurationFields {
		ret[field] = &schema.Schema{
			Type:                  schema.TypeString,
			Optional:              true,
			Computed:              true,
			Description:           desc,
			ValidateFunc:          provider.ValidateDuration,
			DiffSuppressFunc:      pkiSecretBackendConfigAutoTidySuppressDurationDiff,
			DiffSuppressOnRefresh: true,
		}
	}
	return ret
}

// pkiSecretBackendConfigAutoTidySuppressDurationDiff takes care of adjusting for auto-tidy's bad
// behaviour regarding duration fields. Although the fields can be specified with duration
// strings (e.g. "1h2m3s"), the value is always returned as the number of seconds. There is
// one exception: pause_duration.
func pkiSecretBackendConfigAutoTidySuppressDurationDiff(key, oldValue, newValue string, _ *schema.ResourceData) bool {
	if _, isDuration := pkiSecretBackendConfigAutoTidyDurationFields[key]; !isDuration {
		return false
	}
	// The old value is what is returned by auto-tidy config. It will be either the empty
	// string or the number of seconds. In the case of pause_duration which does return
	// a duration string, Atoi() will fail making this function return false, which is
	// the correct thing to do since we don't want to suppress the diff in that case.
	seconds, err := strconv.Atoi(oldValue)
	if err != nil {
		return false
	}
	// The new value is what we have in the state, which will be a duration string.
	duration, err := time.ParseDuration(newValue)
	if err != nil {
		return false
	}
	return seconds == int(duration.Seconds())
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

	data := map[string]interface{}{}

	for k, s := range pkiSecretBackendConfigAutoTidySchema() {
		if k == consts.FieldBackend {
			continue
		}
		if s.Type == schema.TypeBool {
			data[k] = d.Get(k)
		} else { // all other fields are duration strings
			if v, ok := d.GetOk(k); ok {
				data[k] = v
			}
		}
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

	backend, found := strings.CutSuffix(path, "/config/auto-tidy")
	if !found {
		return diag.Errorf("error parsing backend from ID %s", path)
	}
	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
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

	for k := range pkiSecretBackendConfigAutoTidySchema() {
		if k == consts.FieldBackend {
			continue
		}
		if v, ok := config.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
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
