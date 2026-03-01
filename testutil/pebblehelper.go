package testutil

import (
	"archive/tar"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/docker"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

type PebbleOptions struct {
	NetworkName           string
	DNSServer             string
	RejectNoncePercentage uint8
}

func (pebbleOpts *PebbleOptions) SetRejectNoncePercentage(pct uint8) *PebbleOptions {
	pebbleOpts.RejectNoncePercentage = pct
	return pebbleOpts
}

func (pebbleOpts *PebbleOptions) SetDNSServer(server string) *PebbleOptions {
	pebbleOpts.DNSServer = server
	return pebbleOpts
}

func (pebbleOpts *PebbleOptions) SetNetworkName(name string) *PebbleOptions {
	pebbleOpts.NetworkName = name
	return pebbleOpts
}

func NewPebbleOptions() *PebbleOptions {
	return &PebbleOptions{
		RejectNoncePercentage: 25,
	}
}

// setupPebbleAcmeServer creates an instance of the LetsEncrypt Pebble ACME test server
// on a random port and returns the CA for the listener and the port number of the ACME server.
// The ACME server is available on localhost:<port>/dir
func SetupPebbleAcmeServer(t *testing.T) (string, int) {
	ca, port, _ := SetupPebbleAcmeServerWithOption(t, NewPebbleOptions())
	return ca, port
}

func SetupPebbleAcmeServerWithOption(t *testing.T, options *PebbleOptions) (string, int, string) {
	opts := docker.RunOptions{
		ImageRepo:     "docker.mirror.hashicorp.services/letsencrypt/pebble",
		ImageTag:      "latest",
		Cmd:           []string{"pebble", "-config=test/config/pebble-config.json", "-strict=false"},
		ContainerName: "pebble",
		Ports:         []string{"14000/tcp", "15000/tcp"}, // 14000 is the ACME service, 15000 is a mgmt interface
		LogConsumer: func(s string) {
			// t.Log(s)
		},
		ExtraHosts:  []string{"host.docker.internal:host-gateway"},
		Env:         []string{"PEBBLE_WFE_NONCEREJECT=" + strconv.Itoa(int(options.RejectNoncePercentage))},
		NetworkName: options.NetworkName,
	}
	if options.DNSServer != "" {
		opts.Cmd = append(opts.Cmd, "-dnsserver="+options.DNSServer)
	}

	runner, err := docker.NewServiceRunner(opts)
	require.NoError(t, err)

	// Using t.Context here results in context deadline exceeded during the
	// service.Cleanup call, leaving behind the docker container and wasting
	// 10 seconds.
	ctx := context.Background()
	service, _, err := runner.StartNewService(ctx, true, true, func(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
		// Test to see if our ACME directory is reachable.
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		ac := &acme.Client{
			HTTPClient:   &http.Client{Transport: tr},
			DirectoryURL: fmt.Sprintf("https://localhost:%d/dir", port),
		}

		if _, err := ac.Discover(t.Context()); err != nil {
			return nil, err
		}

		return docker.NewServiceHostPort(host, port), nil
	})
	require.NoError(t, err)
	t.Cleanup(service.Cleanup)

	rdr, _, err := runner.DockerAPI.CopyFromContainer(t.Context(), service.Container.ID, "test/certs/pebble.minica.pem")
	require.NoError(t, err)
	defer rdr.Close()

	tr := tar.NewReader(rdr)
	_, err = tr.Next()
	require.NoError(t, err)

	pebbleCa, err := io.ReadAll(tr)
	require.NoError(t, err)

	acmePort, err := strconv.Atoi(strings.Split(service.StartResult.Addrs[0], ":")[1])
	require.NoError(t, err)

	networkAddr := ""
	if options.NetworkName != "" {
		networkAddr = service.Container.NetworkSettings.Networks[options.NetworkName].IPAddress + ":14000"
	}
	return string(pebbleCa), acmePort, networkAddr
}
