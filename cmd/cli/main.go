package main

import (
	"grpc-nmap-vulners/pkg/vulners"
	"log"
)

func main() {
	response, err := vulners.ScanWithNmap([]string{"87.249.43.21"}, "22,")
	log.Printf("%v\n%v\n", response, err)
}
