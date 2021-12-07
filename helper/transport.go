package helper

// Customized copy of github.com/hashicorp/terraform-plugin-sdk/helper/logging/transport.go (v2)

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/salt"
)

// TransportOptions for transport.
type TransportOptions struct {
	// HMACRequestHeaders ensure that any configured header's value is
	// never revealed during logging operations.
	HMACRequestHeaders []string
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

		reqData, err := httputil.DumpRequestOut(req, true)
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
		respData, err := httputil.DumpResponse(resp, true)
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
