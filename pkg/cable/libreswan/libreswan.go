package libreswan

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/kelseyhightower/envconfig"
	"k8s.io/klog"

	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/types"
)

const (
	cableDriverName = "libreswan"
)

func init() {
	cable.AddDriver(cableDriverName, NewLibreSwan)
}

type libreSwan struct {
	secretKey string

	debug   bool
	logFile string

	localEndpoint types.SubmarinerEndpoint
	localSubnets  []string

	// TODO Drop this
	connections []string
}

type specification struct {
	PSK      string
	Debug    bool
	LogFile  string
	IKEPort  string `default:"500"`
	NATTPort string `default:"4500"`
}

// NewLibreSwan starts an IKE daemon using LibreSwan and configures it to manage Submariner's endpoints
func NewLibreSwan(localSubnets []string, localEndpoint types.SubmarinerEndpoint) (cable.Driver, error) {
	// TODO Extract the IPsec spec
	ipSecSpec := specification{}

	err := envconfig.Process("ce_ipsec", &ipSecSpec)
	if err != nil {
		return nil, fmt.Errorf("error processing environment config for ce_ipsec: %v", err)
	}

	return &libreSwan{
		secretKey:     ipSecSpec.PSK,
		debug:         ipSecSpec.Debug,
		logFile:       ipSecSpec.LogFile,
		localEndpoint: localEndpoint,
		localSubnets:  localSubnets,
		connections:   []string{},
	}, nil
}

// GetName returns driver's name
func (i *libreSwan) GetName() string {
	return cableDriverName
}

// Init initializes the driver with any state it needs.
func (i *libreSwan) Init() error {
	// Write the secrets file:
	// %any %any : PSK "secret"
	// TODO Check whether the file already exists
	file, err := os.Create("/etc/ipsec.d/submariner.secrets")
	if err != nil {
		return fmt.Errorf("Error creating the secrets file: %v", err)
	}
	defer file.Close()

	fmt.Fprintf(file, "%%any %%any : PSK \"%s\"\n", i.secretKey)

	// Ensure Pluto is started
	if err := runPluto(i.debug, i.logFile); err != nil {
		return fmt.Errorf("Error starting Pluto: %v", err)
	}
	return nil
}

// GetActiveConnections returns an array of all the active connections for the given cluster.
func (i *libreSwan) GetActiveConnections(clusterID string) ([]string, error) {
	klog.Infof("Active connections: %v", i.connections)
	return i.connections, nil
}

// GetConnections() returns an array of the existing connections, including status and endpoint info
func (i *libreSwan) GetConnections() (*[]v1.Connection, error) {
	connections := make([]v1.Connection, 0)
	return &connections, nil
}

// ConnectToEndpoint establishes a connection to the given endpoint and returns a string
// representation of the IP address of the target endpoint.
func (i *libreSwan) ConnectToEndpoint(endpoint types.SubmarinerEndpoint) (string, error) {
	var localEndpointIP, remoteEndpointIP string

	if endpoint.Spec.NATEnabled {
		localEndpointIP = i.localEndpoint.Spec.PublicIP
		remoteEndpointIP = endpoint.Spec.PublicIP
	} else {
		localEndpointIP = i.localEndpoint.Spec.PrivateIP
		remoteEndpointIP = endpoint.Spec.PrivateIP
	}

	// Subnets
	leftSubnets := []string{}
	for _, subnet := range i.localSubnets {
		if !strings.HasPrefix(subnet, localEndpointIP) {
			leftSubnets = append(leftSubnets, subnet)
		}
	}
	rightSubnets := []string{}
	for _, subnet := range endpoint.Spec.Subnets {
		if !strings.HasPrefix(subnet, remoteEndpointIP) {
			rightSubnets = append(rightSubnets, subnet)
		}
	}

	// Ensure we’re listening
	cmd := exec.Command("/usr/libexec/ipsec/whack", "--listen")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Error listening: %v", err)
	}

	if len(leftSubnets) > 0 && len(rightSubnets) > 0 {
		for lsi := range leftSubnets {
			for rsi := range rightSubnets {
				connectionName := fmt.Sprintf("%s-%d-%d", endpoint.Spec.CableName, lsi, rsi)

				args := []string{}

				args = append(args, "--psk", "--encrypt")
				args = append(args, "--name", connectionName)

				// Left-hand side
				args = append(args, "--host", localEndpointIP)
				args = append(args, "--client", leftSubnets[lsi])

				args = append(args, "--to")

				// Right-hand side
				args = append(args, "--host", remoteEndpointIP)
				args = append(args, "--client", rightSubnets[rsi])

				klog.Infof("Creating connection to %v", endpoint)
				klog.Infof("Whacking with %v", args)

				cmd = exec.Command("/usr/libexec/ipsec/whack", args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr

				if err := cmd.Run(); err != nil {
					//return "", fmt
					klog.Errorf("Error adding a connection with args %v: %v", args, err)
				}

				/*
					if err := Route(endpoint.Spec.CableName); err != nil {
						return "", fmt.Errorf("Error routing connection %v: %v", endpoint.Spec.CableName, err)
					}

					if err := Initiate(endpoint.Spec.CableName); err != nil {
						return "", fmt.Errorf("Error initiating connection %v: %v", endpoint.Spec.CableName, err)
					}
				*/

				cmd = exec.Command("/usr/libexec/ipsec/whack", "--route", "--name", connectionName)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr

				if err := cmd.Run(); err != nil {
					//return "", fmt
					klog.Errorf("Error routing connection %s: %v", connectionName, err)
				}

				cmd = exec.Command("/usr/libexec/ipsec/whack", "--initiate", "--name", connectionName)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr

				if err := cmd.Run(); err != nil {
					//return "", fmt
					klog.Errorf("Error initiating a connection with args %v: %v", args, err)
				}
			}
		}
	}

	i.connections = append(i.connections, endpoint.Spec.CableName)

	return remoteEndpointIP, nil
}

// DisconnectFromEndpoint disconnects from the connection to the given endpoint.
func (i *libreSwan) DisconnectFromEndpoint(endpoint types.SubmarinerEndpoint) error {
	return fmt.Errorf("Not implemented")
}

func runPluto(debug bool, logFile string) error {
	klog.Info("Starting Pluto")

	args := []string{}

	cmd := exec.Command("/usr/local/bin/pluto", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var outputFile *os.File
	if logFile != "" {
		out, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("Failed to open log file %s: %v", logFile, err)
		}

		cmd.Stdout = out
		cmd.Stderr = out
		outputFile = out
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	if err := cmd.Start(); err != nil {
		// Note - Close handles nil receiver
		outputFile.Close()
		return fmt.Errorf("Error starting the Pluto process wih args %v: %v", args, err)
	}

	go func() {
		defer outputFile.Close()
		klog.Fatalf("Pluto exited: %v", cmd.Wait())
	}()

	return nil
}
