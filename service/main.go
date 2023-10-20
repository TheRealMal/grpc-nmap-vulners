package main

import (
	"context"
	"fmt"
	pb "service/proto"

	"github.com/Ullaakut/nmap"
)

// server is used to implement proto.NetVulnServiceServer.
type server struct {
	pb.UnimplementedNetVulnServiceServer
}

func (s *server) CheckVuln(ctx context.Context, req *pb.CheckVulnRequest) (*pb.CheckVulnResponse, error) {
	return &pb.CheckVulnResponse{}, nil
}

func main() {
	scanWithNmap("87.249.43.21")
}

func scanWithNmap(target string) error {
	scriptArguments := map[string]string{
		"mincvss": "0.0",
	}

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
		nmap.WithScriptArguments(scriptArguments),
		nmap.WithPorts("22"),
	)
	if err != nil {
		return err
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return err
	}

	// Print scanning results
	fmt.Println("Scanning results:")
	for _, host := range result.Hosts {
		fmt.Printf("IP-address: %s\n", host.Addresses[0])
		for _, port := range host.Ports {
			fmt.Printf("Port: %d/%s\n", port.ID, port.Protocol)
			fmt.Printf("Status: %s\n", port.State.String())
			fmt.Println("Vulners:")
			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					for _, table := range script.Tables {
						for _, vulnElement := range table.Tables {
							identifier := vulnElement.Elements[1].Value
							cvss_score := vulnElement.Elements[0].Value
							fmt.Printf("\t– %v %v\n", identifier, cvss_score)
						}
					}
					break
				}
			}
		}
	}

	// Print warnings
	if len(warnings) > 0 {
		fmt.Println("Warnings:")
		for _, warning := range warnings {
			fmt.Println(warning)
		}
	}
	return nil
}
