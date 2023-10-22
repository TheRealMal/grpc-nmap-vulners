package vulners

import (
	"grpc-nmap-vulners/pkg/proto"
	"strconv"
	"strings"

	"github.com/Ullaakut/nmap"
)

func requestScanWithNmap(req *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	ports := strings.Builder{}
	for _, port := range req.TcpPort {
		portString := strconv.FormatInt(int64(port), 10)
		if len(portString) == 0 {
			continue
		}
		ports.WriteString(portString)
		ports.WriteString(",")
	}
	portsString := ports.String()
	response, err := ScanWithNmap(req.Targets, portsString)
	if err != nil {
		return nil, err
	}
	return response, nil

}

// ScanWithNmap function to run nmap w/ vulners.nse for provided
// target IPs and ports
func ScanWithNmap(targets []string, ports string) (*proto.CheckVulnResponse, error) {
	response := &proto.CheckVulnResponse{
		Results: []*proto.TargetResult{},
	}
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets...),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
		nmap.WithScriptArguments(map[string]string{"mincvss": "0.0"}),
		nmap.WithPorts(ports),
	)
	if err != nil {
		return nil, err
	}

	result, _, err := scanner.Run()
	if err != nil {
		return nil, err
	}

	for _, host := range result.Hosts {
		hostResult := &proto.TargetResult{
			Target:   host.Addresses[0].String(),
			Services: []*proto.Service{},
		}

		for _, port := range host.Ports {
			portResult := &proto.Service{
				Name:    "default",
				Version: "default",
				TcpPort: int32(port.ID),
				Vulns:   []*proto.Vulnerability{},
			}

			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					for _, table := range script.Tables {
						for _, vulnElement := range table.Tables {
							cvssScore, err := strconv.ParseFloat(vulnElement.Elements[0].Value, 32)
							if err != nil {
								continue
							}

							vulnResult := &proto.Vulnerability{
								Identifier: vulnElement.Elements[1].Value,
								CvssScore:  float32(cvssScore),
							}
							portResult.Vulns = append(portResult.Vulns, vulnResult)
						}
					}
					break
				}
			}

			hostResult.Services = append(hostResult.Services, portResult)
		}
		response.Results = append(response.Results, hostResult)
	}
	return response, nil
}
