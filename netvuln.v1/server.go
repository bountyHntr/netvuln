package netvuln_v1

import (
	context "context"
	"log"
	"os/exec"
	"strconv"

	"github.com/Ullaakut/nmap/v3"
	"github.com/pkg/errors"
)

type NetVulnServer struct {
	UnimplementedNetVulnServiceServer
	nmapPath string
}

func NewNetVulnServer() (*NetVulnServer, error) {
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		return nil, errors.Wrap(err, "failed to find path to nmap")
	}
	return &NetVulnServer{nmapPath: nmapPath}, nil
}

func (s *NetVulnServer) CheckVuln(ctx context.Context, in *CheckVulnRequest) (*CheckVulnResponse, error) {

	scanner, err := s.newScanner(ctx, in.Targets, in.TcpPorts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create nmap scaner")
	}

	result, err := runScanner(scanner)
	if err != nil {
		return nil, errors.Wrap(err, "failed to run nmap scan")
	}
	_ = result

	return &CheckVulnResponse{}, nil
}

const sciptName = "vulners"

func (s *NetVulnServer) newScanner(ctx context.Context, targets []string, tcpPorts []int32) (*nmap.Scanner, error) {

	ports := make([]string, 0, len(tcpPorts))
	for _, port := range tcpPorts {
		ports = append(ports, strconv.Itoa(int(port)))
	}

	return nmap.NewScanner(
		ctx,
		nmap.WithBinaryPath(s.nmapPath),
		nmap.WithTargets(targets...),
		nmap.WithPorts(ports...),
		nmap.WithServiceInfo(),
		nmap.WithScripts(sciptName),
	)
}

func runScanner(scanner *nmap.Scanner) (*nmap.Run, error) {
	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings)
	}

	return result, err
}
