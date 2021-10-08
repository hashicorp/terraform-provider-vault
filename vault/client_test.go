package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestClientFactory_recordStates(t *testing.T) {
	b64enc := func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	}

	tests := []struct {
		name     string
		expected []string
		resp     []*api.Response
	}{
		{
			name: "single",
			resp: []*api.Response{
				{
					Response: &http.Response{
						Header: map[string][]string{
							indexHeaderName: {
								b64enc("v1:cid:1:0:"),
							},
						},
					},
				},
			},
			expected: []string{
				b64enc("v1:cid:1:0:"),
			},
		},
		{
			name: "empty",
			resp: []*api.Response{
				{
					Response: &http.Response{
						Header: map[string][]string{},
					},
				},
			},
			expected: []string{},
		},
		{
			name: "multiple",
			resp: []*api.Response{
				{
					Response: &http.Response{
						Header: map[string][]string{
							indexHeaderName: {
								b64enc("v1:cid:0:1:"),
							},
						},
					},
				},
				{
					Response: &http.Response{
						Header: map[string][]string{
							indexHeaderName: {
								b64enc("v1:cid:1:0:"),
							},
						},
					},
				},
			},
			expected: []string{
				b64enc("v1:cid:0:1:"),
				b64enc("v1:cid:1:0:"),
			},
		},
		{
			name: "duplicates",
			resp: []*api.Response{
				{
					Response: &http.Response{
						Header: map[string][]string{
							indexHeaderName: {
								b64enc("v1:cid:1:0:"),
							},
						},
					},
				},
				{
					Response: &http.Response{
						Header: map[string][]string{
							indexHeaderName: {
								b64enc("v1:cid:1:0:"),
							},
						},
					},
				},
			},
			expected: []string{
				b64enc("v1:cid:1:0:"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &ClientFactory{
				states: []string{},
			}

			var wg sync.WaitGroup
			for _, r := range tt.resp {
				wg.Add(1)
				go func(r *api.Response) {
					defer wg.Done()
					w.recordStates(r)
				}(r)
			}
			wg.Wait()

			if !reflect.DeepEqual(tt.expected, w.states) {
				t.Errorf("recordStates(): expected states %v, actual %v", tt.expected, w.states)
			}
		})
	}
}

func TestClientFactory_requireStates(t *testing.T) {
	tests := []struct {
		name     string
		states   []string
		req      []*api.Request
		expected []string
	}{
		{
			name:   "empty",
			states: []string{},
			req: []*api.Request{
				{
					Headers: make(http.Header),
				},
			},
			expected: []string{},
		},
		{
			name: "basic",
			states: []string{
				"v1:cid:0:1:",
				"v1:cid:1:0:",
			},
			req: []*api.Request{
				{
					Headers: make(http.Header),
				},
			},
			expected: []string{
				"v1:cid:0:1:",
				"v1:cid:1:0:",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &ClientFactory{
				states: tt.states,
			}

			var wg sync.WaitGroup
			for _, r := range tt.req {
				wg.Add(1)
				go func(r *api.Request) {
					defer wg.Done()
					w.requireStates(r)
				}(r)
			}
			wg.Wait()

			actual := []string{}
			for _, r := range tt.req {
				if values := r.Headers.Values(indexHeaderName); len(values) > 0 {
					actual = append(actual, values...)
				}
			}
			sort.Strings(actual)
			if !reflect.DeepEqual(tt.expected, actual) {
				t.Errorf("requireStates(): expected states %v, actual %v", tt.expected, actual)
			}
		})
	}
}

func testHTTPServer(t *testing.T, address string, handler http.Handler) (net.Listener, *http.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: handler,
	}
	go server.Serve(ln)

	return ln, server
}

func TestClientFactory_Client(t *testing.T) {
	b64enc := func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set(indexHeaderName, strings.TrimLeft(req.URL.Path, "/"))
	})

	tests := []struct {
		name       string
		handler    http.Handler
		wantStates []string
		states     []string
	}{
		{
			name:    "basic",
			handler: handler,
			wantStates: []string{
				b64enc("v1:cid:0:1:"),
			},
			states: []string{
				b64enc("v1:cid:0:1:"),
			},
		},
		{
			name:    "multiple",
			handler: handler,
			wantStates: []string{
				b64enc("v1:cid:0:1:"),
				b64enc("v1:cid:1:0:"),
			},
			states: []string{
				b64enc("v1:cid:0:1:"),
				b64enc("v1:cid:1:0:"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := api.DefaultConfig()

			ln, server := testHTTPServer(t, "127.0.0.1:0", tt.handler)
			defer server.Close()

			config.Address = fmt.Sprintf("http://%s", ln.Addr())

			w, err := NewClientFactory(config)
			if err != nil {
				t.Fatal(err)
			}

			if actual := w.Client(); !reflect.DeepEqual(actual, w.client) {
				t.Errorf("Client(): expected %v, actual %v", actual, w.client)
			}

			client := w.Client()
			var wg sync.WaitGroup
			for _, expected := range tt.states {
				wg.Add(1)
				go func(expected string) {
					defer wg.Done()

					req := client.NewRequest("GET", "/"+expected)
					req.Headers.Set(indexHeaderName, expected)
					resp, err := client.RawRequestWithContext(context.Background(), req)
					if err != nil {
						t.Fatal(err)
					}
					// validate that the server provided a valid header value in its response
					actual := resp.Header.Get(indexHeaderName)
					if actual != expected {
						t.Errorf("expected header value %v, actual %v", expected, actual)
					}
				}(expected)
			}
			wg.Wait()

			if !reflect.DeepEqual(tt.wantStates, w.states) {
				t.Errorf("RawRequestWithContext(): expected states %v, actual %v", tt.wantStates, w.states)
			}
		})
	}
}

// TODO : add tests for Clone() especially focused on testing concurrency
