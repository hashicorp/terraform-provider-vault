// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helper

// Customized copy of github.com/hashicorp/terraform-plugin-sdk/helper/logging/transport.go (v2)

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/salt"
)

const (
	// EnvLogBody enables logging of request and response bodies.
	// Takes precedence over any other log body configuration.
	EnvLogBody = "TERRAFORM_VAULT_LOG_BODY"
	// EnvLogRequestBody enables logging the request body.
	EnvLogRequestBody = "TERRAFORM_VAULT_LOG_REQUEST_BODY"
	// EnvLogResponseBody enables logging the response body.
	EnvLogResponseBody = "TERRAFORM_VAULT_LOG_RESPONSE_BODY"
)

// TransportOptions for transport.
type TransportOptions struct {
	// HMACRequestHeaders ensure that any configured header's value is
	// never revealed during logging operations.
	HMACRequestHeaders []string
	// LogRequestBody for all requests, ideally this would only be enabled for debug purposes,
	// since the request body might contain secrets.
	LogRequestBody bool
	// LogResponseBody for all responses, ideally this would only be enabled for debug purposes,
	// since the response body might contain secrets.
	LogResponseBody bool
}

// DefaultTransportOptions for setting up the HTTP transport wrapper.
func DefaultTransportOptions() *TransportOptions {
	opts := &TransportOptions{
		HMACRequestHeaders: []string{
			"X-Vault-Token",
		},
	}

	if logBody, err := strconv.ParseBool(os.Getenv(EnvLogBody)); err == nil {
		opts.LogRequestBody = logBody
		opts.LogResponseBody = logBody
	} else {
		if logRequestBody, err := strconv.ParseBool(os.Getenv(EnvLogRequestBody)); err == nil {
			opts.LogRequestBody = logRequestBody
		}
		if logResponseBody, err := strconv.ParseBool(os.Getenv(EnvLogResponseBody)); err == nil {
			opts.LogResponseBody = logResponseBody
		}
	}

	return opts
}

type transport struct {
	name      string
	transport http.RoundTripper
	options   *TransportOptions
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if logging.IsDebugOrHigher() {
		var origHeaders http.Header
		if len(t.options.HMACRequestHeaders) > 0 && len(req.Header) > 0 {
			origHeaders = req.Header.Clone()
			s := salt.NewNonpersistentSalt()
			for _, k := range t.options.HMACRequestHeaders {
				if len(req.Header.Values(k)) == 0 {
					continue
				}

				req.Header.Del(k)
				for _, v := range origHeaders[k] {
					req.Header.Add(k, s.GetIdentifiedHMAC(v))
				}
			}
		}

		reqData, err := httputil.DumpRequestOut(req, t.options.LogRequestBody)
		if err == nil {
			log.Printf("[DEBUG] "+logReqMsg, t.name, prettyPrintJsonLines(reqData))
		} else {
			log.Printf("[ERROR] %s API Request error: %#v", t.name, err)
		}

		if origHeaders != nil {
			req.Header = origHeaders
		}
	}

	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	if logging.IsDebugOrHigher() {
		respData, err := httputil.DumpResponse(resp, t.options.LogResponseBody)
		if err == nil {
			log.Printf("[DEBUG] "+logRespMsg, t.name, prettyPrintJsonLines(respData))
		} else {
			log.Printf("[ERROR] %s API Response error: %#v", t.name, err)
		}
	}

	return resp, nil
}

func NewTransport(name string, t http.RoundTripper, opts *TransportOptions) *transport {
	return &transport{
		name:      name,
		transport: t,
		options:   opts,
	}
}

// prettyPrintJsonLines iterates through a []byte line-by-line,
// transforming any lines that are complete json into pretty-printed json.
func prettyPrintJsonLines(b []byte) string {
	parts := strings.Split(string(b), "\n")
	for i, p := range parts {
		if b := []byte(p); json.Valid(b) {
			var out bytes.Buffer
			json.Indent(&out, b, "", " ")
			parts[i] = out.String()
		}
	}
	return strings.Join(parts, "\n")
}

const logReqMsg = `%s API Request Details:
---[ REQUEST ]---------------------------------------
%s
-----------------------------------------------------`

const logRespMsg = `%s API Response Details:
---[ RESPONSE ]--------------------------------------
%s
-----------------------------------------------------`
