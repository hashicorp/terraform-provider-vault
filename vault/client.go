package vault

import (
	"sync"

	"github.com/hashicorp/vault/api"
)

const indexHeaderName = "X-Vault-Index"

// ClientFactory ensures a consistent way of managing Vault clients for the provider.
// The factory ensures that all api.Client instances support the Client Controlled Consistency
// model (VLT-146).
// All Client instances share the same replication state store.
type ClientFactory struct {
	m      *sync.RWMutex
	client *api.Client
	states []string
}

// Client for this factory
func (w *ClientFactory) Client() *api.Client {
	return w.client
}

// Clone this factory's Client
func (w *ClientFactory) Clone() (*api.Client, error) {
	c, err := w.Client().Clone()
	if err != nil {
		return nil, err
	}
	return w.registerCallbacks(c), nil
}

func (w *ClientFactory) init() {
	w.m.Lock()
	defer w.m.Unlock()
	if w.states != nil {
		panic("already initialized")
	}
	w.states = []string{}
	w.client = w.registerCallbacks(w.client)
}

func (w *ClientFactory) registerCallbacks(c *api.Client) *api.Client {
	return c.WithRequestCallbacks(w.requireStates).
		WithResponseCallbacks(w.recordStates)
}

func (w *ClientFactory) recordStates(resp *api.Response) {
	w.m.Lock()
	defer w.m.Unlock()
	newState := resp.Header.Get(indexHeaderName)
	if newState != "" {
		w.states = api.MergeReplicationStates(w.states, newState)
	}
}

func (w *ClientFactory) requireStates(req *api.Request) {
	w.m.RLock()
	defer w.m.RUnlock()
	for _, s := range w.states {
		req.Headers.Add(indexHeaderName, s)
	}
}

// NewClientFactory sets up a new ClientFactory
func NewClientFactory(config *api.Config) (*ClientFactory, error) {
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	wrapper := &ClientFactory{
		m:      &sync.RWMutex{},
		client: client,
	}
	wrapper.init()

	return wrapper, nil
}
