package testcontainer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"github.com/hashicorp/go-uuid"
)

type Runner struct {
	DockerAPI  *client.Client
	RunOptions RunOptions
}

type RunOptions struct {
	ImageRepo              string
	ImageTag               string
	ContainerName          string
	Cmd                    []string
	Entrypoint             []string
	Env                    []string
	NetworkName            string
	NetworkID              string
	CopyFromTo             map[string]string
	Ports                  []string
	DoNotAutoRemove        bool
	AuthUsername           string
	AuthPassword           string
	OmitLogTimestamps      bool
	LogConsumer            func(string)
	Capabilities           []string
	PreDelete              bool
	PostStart              func(string, string) error
	LogStderr              io.Writer
	LogStdout              io.Writer
	VolumeNameToMountPoint map[string]string
}

const DockerAPIVersion = "1.40"

func NewDockerAPI() (*client.Client, error) {
	return client.NewClientWithOpts(client.FromEnv, client.WithVersion(DockerAPIVersion))
}

func NewServiceRunner(opts RunOptions) (*Runner, error) {
	dapi, err := NewDockerAPI()
	if err != nil {
		return nil, err
	}

	if opts.NetworkName == "" {
		opts.NetworkName = os.Getenv("TEST_DOCKER_NETWORK_NAME")
	}
	if opts.NetworkName != "" {
		nets, err := dapi.NetworkList(context.TODO(), types.NetworkListOptions{
			Filters: filters.NewArgs(filters.Arg("name", opts.NetworkName)),
		})
		if err != nil {
			return nil, err
		}
		if len(nets) != 1 {
			return nil, fmt.Errorf("expected exactly one docker network named %q, got %d", opts.NetworkName, len(nets))
		}
		opts.NetworkID = nets[0].ID
	}
	if opts.NetworkID == "" {
		opts.NetworkID = os.Getenv("TEST_DOCKER_NETWORK_ID")
	}
	if opts.ContainerName == "" {
		if strings.Contains(opts.ImageRepo, "/") {
			return nil, fmt.Errorf("ContainerName is required for non-library images")
		}
		// If there's no slash in the repo it's almost certainly going to be
		// a good container name.
		opts.ContainerName = opts.ImageRepo
	}
	return &Runner{
		DockerAPI:  dapi,
		RunOptions: opts,
	}, nil
}

type ServiceConfig interface {
	Address() string
	URL() *url.URL
}

func NewServiceHostPort(host string, port int) *ServiceHostPort {
	return &ServiceHostPort{address: fmt.Sprintf("%s:%d", host, port)}
}

func NewServiceHostPortParse(s string) (*ServiceHostPort, error) {
	pieces := strings.Split(s, ":")
	if len(pieces) != 2 {
		return nil, fmt.Errorf("address must be of the form host:port, got: %v", s)
	}

	port, err := strconv.Atoi(pieces[1])
	if err != nil || port < 1 {
		return nil, fmt.Errorf("address must be of the form host:port, got: %v", s)
	}

	return &ServiceHostPort{s}, nil
}

type ServiceHostPort struct {
	address string
}

func (s ServiceHostPort) Address() string {
	return s.address
}

func (s ServiceHostPort) URL() *url.URL {
	return &url.URL{Host: s.address}
}

func NewServiceURLParse(s string) (*ServiceURL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return &ServiceURL{u: *u}, nil
}

func NewServiceURL(u url.URL) *ServiceURL {
	return &ServiceURL{u: u}
}

type ServiceURL struct {
	u url.URL
}

func (s ServiceURL) Address() string {
	return s.u.Host
}

func (s ServiceURL) URL() *url.URL {
	return &s.u
}

// ServiceAdapter verifies connectivity to the service, then returns either the
// connection string (typically a URL) and nil, or empty string and an error.
type ServiceAdapter func(ctx context.Context, host string, port int) (ServiceConfig, error)

// StartService will start the runner's configured docker container with a
// random UUID suffix appended to the name to make it unique and will return
// either a hostname or local address depending on if a Docker network was given.
//
// Most tests can default to using this.
func (d *Runner) StartService(ctx context.Context, connect ServiceAdapter) (*Service, error) {
	serv, _, err := d.StartNewService(ctx, true, false, connect)

	return serv, err
}

type LogConsumerWriter struct {
	consumer func(string)
}

func (l LogConsumerWriter) Write(p []byte) (n int, err error) {
	// TODO this assumes that we're never passed partial log lines, which
	// seems a safe assumption for now based on how docker looks to implement
	// logging, but might change in the future.
	scanner := bufio.NewScanner(bytes.NewReader(p))
	scanner.Buffer(make([]byte, 64*1024), bufio.MaxScanTokenSize)
	for scanner.Scan() {
		l.consumer(scanner.Text())
	}
	return len(p), nil
}

var _ io.Writer = &LogConsumerWriter{}

// StartNewService will start the runner's configured docker container but with the
// ability to control adding a name suffix or forcing a local address to be returned.
// 'addSuffix' will add a random UUID to the end of the container name.
// 'forceLocalAddr' will force the container address returned to be in the
// form of '127.0.0.1:1234' where 1234 is the mapped container port.
func (d *Runner) StartNewService(ctx context.Context, addSuffix, forceLocalAddr bool, connect ServiceAdapter) (*Service, string, error) {
	if d.RunOptions.PreDelete {
		name := d.RunOptions.ContainerName
		matches, err := d.DockerAPI.ContainerList(ctx, types.ContainerListOptions{
			All: true,
			// TODO use labels to ensure we don't delete anything we shouldn't
			Filters: filters.NewArgs(
				filters.Arg("name", name),
			),
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to list containers named %q", name)
		}
		for _, cont := range matches {
			err = d.DockerAPI.ContainerRemove(ctx, cont.ID, types.ContainerRemoveOptions{Force: true})
			if err != nil {
				return nil, "", fmt.Errorf("failed to pre-delete container named %q", name)
			}
		}
	}
	result, err := d.Start(context.Background(), addSuffix, forceLocalAddr)
	if err != nil {
		return nil, "", err
	}

	// The waitgroup wg is used here to support some stuff in NewDockerCluster.
	// We can't generate the PKI cert for the https listener until we know the
	// container's address, meaning we must first start the container, then
	// generate the cert, then copy it into the container, then signal Vault
	// to reload its config/certs.  However, if we SIGHUP Vault before Vault
	// has installed its signal handler, that will kill Vault, since the default
	// behaviour for HUP is termination.  So the PostStart that NewDockerCluster
	// passes in (which does all that PKI cert stuff) waits to see output from
	// Vault on stdout/stderr before it sends the signal, and we don't want to
	// run the PostStart until we've hooked into the docker logs.
	var wg sync.WaitGroup
	logConsumer := d.createLogConsumer(result.Container.ID, &wg)

	if logConsumer != nil {
		wg.Add(1)
		go logConsumer()
	}
	wg.Wait()

	if d.RunOptions.PostStart != nil {
		if err := d.RunOptions.PostStart(result.Container.ID, result.RealIP); err != nil {
			return nil, "", fmt.Errorf("poststart failed: %w", err)
		}
	}

	cleanup := func() {
		for i := 0; i < 10; i++ {
			err := d.DockerAPI.ContainerRemove(ctx, result.Container.ID, types.ContainerRemoveOptions{Force: true})
			if err == nil || client.IsErrNotFound(err) {
				return
			}
			time.Sleep(1 * time.Second)
		}
	}

	bo := backoff.NewExponentialBackOff()
	bo.MaxInterval = time.Second * 5
	bo.MaxElapsedTime = 2 * time.Minute

	pieces := strings.Split(result.Addrs[0], ":")
	portInt, err := strconv.Atoi(pieces[1])
	if err != nil {
		return nil, "", err
	}

	var config ServiceConfig
	err = backoff.Retry(func() error {
		container, err := d.DockerAPI.ContainerInspect(ctx, result.Container.ID)
		if err != nil || !container.State.Running {
			return backoff.Permanent(fmt.Errorf("failed inspect or container %q not running: %w", result.Container.ID, err))
		}

		c, err := connect(ctx, pieces[0], portInt)
		if err != nil {
			return err
		}
		if c == nil {
			return fmt.Errorf("service adapter returned nil error and config")
		}
		config = c
		return nil
	}, bo)
	if err != nil {
		if !d.RunOptions.DoNotAutoRemove {
			cleanup()
		}
		return nil, "", err
	}

	return &Service{
		Config:      config,
		Cleanup:     cleanup,
		Container:   result.Container,
		StartResult: result,
	}, result.Container.ID, nil
}

// createLogConsumer returns a function to consume the logs of the container with the given ID.
// If a wait group is given, `WaitGroup.Done()` will be called as soon as the call to the
// ContainerLogs Docker API call is done.
// The returned function will block, so it should be run on a goroutine.
func (d *Runner) createLogConsumer(containerId string, wg *sync.WaitGroup) func() {
	if d.RunOptions.LogStdout != nil && d.RunOptions.LogStderr != nil {
		return func() {
			d.consumeLogs(containerId, wg, d.RunOptions.LogStdout, d.RunOptions.LogStderr)
		}
	}
	if d.RunOptions.LogConsumer != nil {
		return func() {
			d.consumeLogs(containerId, wg, &LogConsumerWriter{d.RunOptions.LogConsumer}, &LogConsumerWriter{d.RunOptions.LogConsumer})
		}
	}
	return nil
}

// consumeLogs is the function called by the function returned by createLogConsumer.
func (d *Runner) consumeLogs(containerId string, wg *sync.WaitGroup, logStdout, logStderr io.Writer) {
	// We must run inside a goroutine because we're using Follow:true,
	// and StdCopy will block until the log stream is closed.
	stream, err := d.DockerAPI.ContainerLogs(context.Background(), containerId, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: !d.RunOptions.OmitLogTimestamps,
		Details:    true,
		Follow:     true,
	})
	wg.Done()
	if err != nil {
		d.RunOptions.LogConsumer(fmt.Sprintf("error reading container logs: %v", err))
	} else {
		_, err := stdcopy.StdCopy(logStdout, logStderr, stream)
		if err != nil {
			d.RunOptions.LogConsumer(fmt.Sprintf("error demultiplexing docker logs: %v", err))
		}
	}
}

type Service struct {
	Config      ServiceConfig
	Cleanup     func()
	Container   *types.ContainerJSON
	StartResult *StartResult
}

type StartResult struct {
	Container *types.ContainerJSON
	Addrs     []string
	RealIP    string
}

func (d *Runner) Start(ctx context.Context, addSuffix, forceLocalAddr bool) (*StartResult, error) {
	name := d.RunOptions.ContainerName
	if addSuffix {
		suffix, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}
		name += "-" + suffix
	}

	cfg := &container.Config{
		Hostname: name,
		Image:    fmt.Sprintf("%s:%s", d.RunOptions.ImageRepo, d.RunOptions.ImageTag),
		Env:      d.RunOptions.Env,
		Cmd:      d.RunOptions.Cmd,
	}
	if len(d.RunOptions.Ports) > 0 {
		cfg.ExposedPorts = make(map[nat.Port]struct{})
		for _, p := range d.RunOptions.Ports {
			cfg.ExposedPorts[nat.Port(p)] = struct{}{}
		}
	}
	if len(d.RunOptions.Entrypoint) > 0 {
		cfg.Entrypoint = strslice.StrSlice(d.RunOptions.Entrypoint)
	}

	hostConfig := &container.HostConfig{
		AutoRemove:      !d.RunOptions.DoNotAutoRemove,
		PublishAllPorts: true,
	}
	if len(d.RunOptions.Capabilities) > 0 {
		hostConfig.CapAdd = d.RunOptions.Capabilities
	}

	netConfig := &network.NetworkingConfig{}
	if d.RunOptions.NetworkID != "" {
		netConfig.EndpointsConfig = map[string]*network.EndpointSettings{
			d.RunOptions.NetworkID: {},
		}
	}

	// best-effort pull
	var opts types.ImageCreateOptions
	if d.RunOptions.AuthUsername != "" && d.RunOptions.AuthPassword != "" {
		var buf bytes.Buffer
		auth := map[string]string{
			"username": d.RunOptions.AuthUsername,
			"password": d.RunOptions.AuthPassword,
		}
		if err := json.NewEncoder(&buf).Encode(auth); err != nil {
			return nil, err
		}
		opts.RegistryAuth = base64.URLEncoding.EncodeToString(buf.Bytes())
	}
	resp, _ := d.DockerAPI.ImageCreate(ctx, cfg.Image, opts)
	if resp != nil {
		_, _ = io.ReadAll(resp)
	}

	c, err := d.DockerAPI.ContainerCreate(ctx, cfg, hostConfig, netConfig, nil, cfg.Hostname)
	if err != nil {
		return nil, fmt.Errorf("container create failed: %v", err)
	}

	err = d.DockerAPI.ContainerStart(ctx, c.ID, types.ContainerStartOptions{})
	if err != nil {
		_ = d.DockerAPI.ContainerRemove(ctx, c.ID, types.ContainerRemoveOptions{})
		return nil, fmt.Errorf("container start failed: %v", err)
	}

	inspect, err := d.DockerAPI.ContainerInspect(ctx, c.ID)
	if err != nil {
		_ = d.DockerAPI.ContainerRemove(ctx, c.ID, types.ContainerRemoveOptions{})
		return nil, err
	}

	var addrs []string
	for _, port := range d.RunOptions.Ports {
		pieces := strings.Split(port, "/")
		if len(pieces) < 2 {
			return nil, fmt.Errorf("expected port of the form 1234/tcp, got: %s", port)
		}
		if d.RunOptions.NetworkID != "" && !forceLocalAddr {
			addrs = append(addrs, fmt.Sprintf("%s:%s", cfg.Hostname, pieces[0]))
		} else {
			mapped, ok := inspect.NetworkSettings.Ports[nat.Port(port)]
			if !ok || len(mapped) == 0 {
				return nil, fmt.Errorf("no port mapping found for %s", port)
			}
			addrs = append(addrs, fmt.Sprintf("127.0.0.1:%s", mapped[0].HostPort))
		}
	}

	var realIP string
	if d.RunOptions.NetworkID == "" {
		if len(inspect.NetworkSettings.Networks) > 1 {
			return nil, fmt.Errorf("set d.RunOptions.NetworkName instead for container with multiple networks: %v", inspect.NetworkSettings.Networks)
		}
		for _, network := range inspect.NetworkSettings.Networks {
			realIP = network.IPAddress
			break
		}
	} else {
		realIP = inspect.NetworkSettings.Networks[d.RunOptions.NetworkName].IPAddress
	}

	return &StartResult{
		Container: &inspect,
		Addrs:     addrs,
		RealIP:    realIP,
	}, nil
}

func (d *Runner) Stop(ctx context.Context, containerID string) error {
	if d.RunOptions.NetworkID != "" {
		if err := d.DockerAPI.NetworkDisconnect(ctx, d.RunOptions.NetworkID, containerID, true); err != nil {
			return fmt.Errorf("error disconnecting network (%v): %v", d.RunOptions.NetworkID, err)
		}
	}

	// timeout in seconds
	timeout := 5
	options := container.StopOptions{
		Timeout: &timeout,
	}
	if err := d.DockerAPI.ContainerStop(ctx, containerID, options); err != nil {
		return fmt.Errorf("error stopping container: %v", err)
	}

	return nil
}
