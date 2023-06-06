package netvuln_v1

import (
	"context"
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

	return buildResponse(result)
}

const scriptName = "vulners"

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
		nmap.WithScripts(scriptName),
	)
}

func runScanner(scanner *nmap.Scanner) (*nmap.Run, error) {
	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("nmap run finished with warnings: %s\n", *warnings)
	}

	return result, err
}

func buildResponse(result *nmap.Run) (*CheckVulnResponse, error) {
	resp := new(CheckVulnResponse)

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		result := &TargetResult{Target: host.Addresses[0].String()}
		for _, port := range host.Ports {
			service := Service{
				Name:    port.Service.Name,
				Version: port.Service.Version,
				TcpPort: int32(port.ID),
			}

			script := filterVulnersScript(port.Scripts)

			vulns, err := parseVulnersScriptResponse(script)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get vulnerabilities")
			}

			service.Vulns = vulns
			result.Services = append(result.Services, &service)
		}

		resp.Results = append(resp.Results, result)
	}

	return resp, nil
}

func filterVulnersScript(scripts []nmap.Script) *nmap.Script {
	for idx := range scripts {
		if scripts[idx].ID != scriptName {
			continue
		}

		return &scripts[idx]
	}

	return nil
}

type vulnersElement struct {
	isExploit bool
	id        string
	cvss      float32
}

func parseVulnersScriptResponse(script *nmap.Script) ([]*Vulnerability, error) {

	vulns := make([]*Vulnerability, 0)

	if script == nil || len(script.Tables) == 0 {
		return vulns, nil
	}

	tables := script.Tables[0].Tables
	for tableIdx := range tables {
		parsedElement, err := parseVulnersElement(tables[tableIdx].Elements)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse vulners response")
		}

		if !parsedElement.isExploit {
			continue
		}

		vulns = append(vulns, &Vulnerability{
			Identifier: parsedElement.id,
			CvssScore:  parsedElement.cvss,
		})
	}

	return vulns, nil
}

func parseVulnersElement(elements []nmap.Element) (vulnersElement, error) {
	vElement := vulnersElement{}

	for _, el := range elements {
		if el.Key == "is_exploit" && el.Value == "false" {
			return vElement, nil
		}
	}

	vElement.isExploit = true

	var cvssStr string
	for _, el := range elements {
		switch el.Key {
		case "id":
			vElement.id = el.Value
		case "cvss":
			cvssStr = el.Value
		}
	}

	cvss, err := strconv.ParseFloat(cvssStr, 32)
	if err != nil {
		return vulnersElement{}, errors.Wrap(err, "failed to parse cvss")
	}
	vElement.cvss = float32(cvss)

	return vElement, nil
}
