package netvuln_v1

import (
	"context"
	"os/exec"
	"strconv"

	"github.com/Ullaakut/nmap/v3"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

type NetVulnServer struct {
	UnimplementedNetVulnServiceServer
	nmapPath string // path to nmap binary
}

func NewNetVulnServer() (*NetVulnServer, error) {
	// save the path to the nmap binary so as not to look for it on every request
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		return nil, errors.Wrap(err, "failed to find path to nmap")
	}
	return &NetVulnServer{nmapPath: nmapPath}, nil
}

func (s *NetVulnServer) CheckVuln(ctx context.Context, in *CheckVulnRequest) (*CheckVulnResponse, error) {
	log.Debugf("new request: %+v", in)

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

// creates a new scanner, the use of which is equivalent to the result of the following command:
// nmap -sV -p [tcpPorts...] --script vulners [targets...]
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
		log.Warn("nmap run finished with warnings:", *warnings)
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

// returns the result of the 'vulners' script or nil
func filterVulnersScript(scripts []nmap.Script) *nmap.Script {
	for idx := range scripts {
		if scripts[idx].ID != scriptName {
			continue
		}

		return &scripts[idx]
	}

	return nil
}

// containing the parsed elements of a row from a 'vulners' script output table
type vulnersElement struct {
	isExploit bool
	id        string
	cvss      float32
}

// parses the result of the 'vulners' script execution and returns the found list of vulnerabilities
func parseVulnersScriptResponse(script *nmap.Script) ([]*Vulnerability, error) {

	vulns := make([]*Vulnerability, 0)

	// if the 'vulners' script was not applied to the current service, then script == nil
	if script == nil || len(script.Tables) == 0 {
		return vulns, nil
	}

	tables := script.Tables[0].Tables // get a table containing a list of all potential vulnerabilities
	for tableIdx := range tables {
		parsedElement, err := parseVulnersElement(tables[tableIdx].Elements)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse vulners response")
		}

		// return only exploits
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

var ErrParseVulners = errors.New("internal error: failed to parse vulner element")

// parse one "row" in the 'vulners' table that corresponds to some potential vulnerability
// on each request, the elements have a different order, so it is necessary to search for each element by key
func parseVulnersElement(elements []nmap.Element) (vulnersElement, error) {
	vElement := vulnersElement{}

	// if the slice "elements" does not contain an element with key "is_exploit", we consider that
	// the row is invalid and the program has an internal error
	isInvalid := true

	for _, el := range elements {
		if el.Key != "is_exploit" {
			continue
		}

		isInvalid = false

		if el.Value == "true" {
			vElement.isExploit = true
			break
		}
	}

	if isInvalid {
		log.Error("failed to parse vulners elements: missing element with key 'is_exploit'")
		return vElement, ErrParseVulners
	}

	// if the row does not contain an exploit, then do not parse "cvss", so as not to waste resources
	// fully process only rows with exploits
	if !vElement.isExploit {
		return vElement, nil
	}

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
