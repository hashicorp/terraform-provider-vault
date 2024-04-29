package testcontainer

import (
	"context"
	"fmt"
	"os"
	"testing"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/vault/sdk/helper/docker"
	"github.com/stretchr/testify/require"
)

type Config struct {
	docker.ServiceHostPort
	Token             string
	ContainerHTTPAddr string
}

func (c *Config) APIConfig() *consulapi.Config {
	apiConfig := consulapi.DefaultConfig()
	apiConfig.Address = c.Address()
	apiConfig.Token = c.Token
	return apiConfig
}

// PrepareTestContainer is a test helper that creates a Consul docker container
// or fails the test if unsuccessful. See RunContainer for more details on the
// configuration.
func PrepareConsulTestContainer(t *testing.T) *Config {
	t.Helper()

	if retAddress := os.Getenv("CONSUL_HTTP_ADDR"); retAddress != "" {
		shp, err := docker.NewServiceHostPortParse(retAddress)
		require.NoError(t, err)
		return &Config{ServiceHostPort: *shp, Token: os.Getenv("CONSUL_HTTP_TOKEN")}
	}

	const (
		config = `acl { enabled = true default_policy = "deny" }`
		name   = "consul"
		repo   = "docker.mirror.hashicorp.services/library/consul"
	)

	dockerOpts := docker.RunOptions{
		ContainerName: name,
		ImageRepo:     repo,
		ImageTag:      "latest",
		Cmd:           []string{"agent", "-dev", "-client", "0.0.0.0", "-hcl", config},
		Ports:         []string{"8500/tcp"},
		AuthUsername:  os.Getenv("CONSUL_DOCKER_USERNAME"),
		AuthPassword:  os.Getenv("CONSUL_DOCKER_PASSWORD"),
	}

	// Add a unique suffix if there is no per-test prefix provided
	runner, err := docker.NewServiceRunner(dockerOpts)
	require.NoError(t, err)

	svc, _, err := runner.StartNewService(context.Background(), true, false, connectConsul)
	require.NoError(t, err)
	t.Cleanup(svc.Cleanup)

	// Find the container network info.
	if len(svc.Container.NetworkSettings.Networks) < 1 {
		t.Fatal("failed to find any network settings for container")
	}
	cfg := svc.Config.(*Config)
	for _, eps := range svc.Container.NetworkSettings.Networks {
		// Just pick the first network, we assume only one for now.
		// Pull out the real container IP and set that up
		cfg.ContainerHTTPAddr = fmt.Sprintf("http://%s:8500", eps.IPAddress)
		break
	}
	return cfg
}

func connectConsul(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
	shp := docker.NewServiceHostPort(host, port)
	apiConfig := consulapi.DefaultNonPooledConfig()
	apiConfig.Address = shp.Address()
	consul, err := consulapi.NewClient(apiConfig)
	if err != nil {
		return nil, err
	}

	// Make sure Consul is up
	if _, err = consul.Status().Leader(); err != nil {
		return nil, err
	}

	return &Config{
		ServiceHostPort: *shp,
	}, nil
}
