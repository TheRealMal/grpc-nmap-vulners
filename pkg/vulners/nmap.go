package vulners

import (
	"grpc-nmap-vulners/pkg/proto"
	"strconv"
	"strings"
	"sync"

	"github.com/Ullaakut/nmap"
)

func requestScanWithNmap(req *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	ports := strings.Builder{}
	for _, port := range req.TcpPort {
		portString := strconv.FormatInt(int64(port), 10)
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

	response := &proto.CheckVulnResponse{
		Results: []*proto.TargetResult{},
	}
	parseHostsToResponse(response, result.Hosts)

	return response, nil
}

func parseHostsToResponse(response *proto.CheckVulnResponse, hosts []nmap.Host) {
	wg := &sync.WaitGroup{}
	mu := &sync.Mutex{}
	for _, host := range hosts {
		wg.Add(1)
		go func(host *nmap.Host) {
			defer wg.Done()
			parseHostToResponse(response, host, mu)
		}(&host)
	}
	wg.Wait()
}

func parseHostToResponse(response *proto.CheckVulnResponse, host *nmap.Host, mu *sync.Mutex) {
	hostResult := &proto.TargetResult{
		Target:   host.Addresses[0].String(),
		Services: []*proto.Service{},
	}

	wg := &sync.WaitGroup{}
	for _, port := range host.Ports {
		wg.Add(1)
		go func(port *nmap.Port) {
			defer wg.Done()
			parsePortToResult(hostResult, port, mu)
		}(&port)
	}
	wg.Wait()

	mu.Lock()
	response.Results = append(response.Results, hostResult)
	mu.Unlock()
}

func parsePortToResult(result *proto.TargetResult, port *nmap.Port, mu *sync.Mutex) {
	portResult := &proto.Service{
		Name:    port.Service.Name,
		Version: port.Service.Version,
		TcpPort: int32(port.ID),
		Vulns:   []*proto.Vulnerability{},
	}

	for _, script := range port.Scripts {
		if script.ID == "vulners" {
			for _, table := range script.Tables {
				for _, vulnElement := range table.Tables {
					cvssScore, err := strconv.ParseFloat(vulnFind(vulnElement.Elements, "cvss"), 32)
					if err != nil {
						continue
					}

					vulnResult := &proto.Vulnerability{
						Identifier: vulnFind(vulnElement.Elements, "id"),
						CvssScore:  float32(cvssScore),
					}
					mu.Lock()
					portResult.Vulns = append(portResult.Vulns, vulnResult)
					mu.Unlock()
				}
			}
			break
		}
	}
	mu.Lock()
	result.Services = append(result.Services, portResult)
	mu.Unlock()
}

func vulnFind(elements []nmap.Element, targetKey string) string {
	for _, element := range elements {
		if element.Key == targetKey {
			return element.Value
		}
	}
	return ""
}
