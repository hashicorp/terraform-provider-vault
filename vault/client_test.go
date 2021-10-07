package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"sort"
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
				m:      &sync.RWMutex{},
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
				m:      &sync.RWMutex{},
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	tests := []struct {
		name       string
		handler    http.Handler
		wantStates []string
	}{
		{
			name: "basic",
			handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set(indexHeaderName, "foo")
			}),
			wantStates: []string{"foo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := api.DefaultConfig()

			ln, server := testHTTPServer(t, "127.0.0.1:0", tt.handler)
			defer server.Close()

			config.Address = fmt.Sprintf("http://%s", ln.Addr())
			client, err := api.NewClient(config)
			if err != nil {
				t.Fatal(err)
			}

			w := &ClientFactory{
				m:      &sync.RWMutex{},
				client: client,
			}
			if got := w.Client(); !reflect.DeepEqual(got, client) {
				t.Errorf("Client() = %v, want %v", got, client)
			}

			// initialize the Client with the expected callbacks
			w.init()

			client = w.Client()
			req := client.NewRequest("GET", "/")
			req.Headers.Set(indexHeaderName, "foo")
			resp, err := client.RawRequestWithContext(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}

			actualValues := resp.Header.Values(indexHeaderName)
			if !reflect.DeepEqual(tt.wantStates, actualValues) {
				t.Errorf("Response(): expected header values %v, actual %v", tt.wantStates, actualValues)
			}

			if !reflect.DeepEqual(tt.wantStates, w.states) {
				t.Errorf("RawRequestWithContext(): expected states %v, actual %v", tt.wantStates, w.states)
			}
		})
	}
}

// TODO : add tests for CLone() especially focused on testing concurrency
